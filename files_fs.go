package main

// File systems for the Files manager: this computer, a node over SSH, and
// the demo's. Paths are always slash paths; on Windows, this computer's
// C:\Users\me is /C/Users/me and / lists the drives.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fileSys is a nodeFS that can also change things.
type fileSys interface {
	nodeFS
	Label() string // "This computer", or the node's name
	Local() bool   // this computer
	Mkdir(p string) error
	Rename(from, to string) error
	Remove(paths []string) error
	ReadHead(p string, max int) ([]byte, error)
	DiskUsage(paths []string) (int64, error)
}

// System folders: browsing is fine, changing them (or anything in them)
// isn't. Top-level folders like /home or /mnt can't be renamed or deleted
// themselves, only what's in them.
var protectedRoots = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
	"/run", "/sbin", "/sys", "/usr", "/var/lib/kubelet", "/var/lib/containerd",
	"/var/lib/etcd", "/var/lib/longhorn", "/var/lib/docker", "/var/log/pods",
	"/C/Windows", "/C/Program Files", "/C/Program Files (x86)", "/C/ProgramData",
}

// protectedPath says why p may not be changed, or "".
func protectedPath(p string) string {
	p = path.Clean("/" + p)
	if p == "/" || strings.Count(p, "/") == 1 || (len(p) == 2 && p[0] == '/') {
		return p + " is a top-level folder"
	}
	for _, r := range protectedRoots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return r + " is a system folder"
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Over SSH (nodebrowser.go has the connection, listing and search)
// ---------------------------------------------------------------------------

func (f *sshFS) Label() string { return f.label }
func (f *sshFS) Local() bool   { return false }

func quoteAll(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = shellQuote(p)
	}
	return strings.Join(q, " ")
}

func (f *sshFS) Mkdir(p string) error {
	_, err := f.run("mkdir -p -- " + shellQuote(p))
	return err
}

func (f *sshFS) Rename(from, to string) error {
	_, err := f.run("[ -e " + shellQuote(to) + " ] && { echo " + shellQuote(path.Base(to)+" already exists") + " >&2; exit 1; }; mv -- " + shellQuote(from) + " " + shellQuote(to))
	return err
}

func (f *sshFS) Remove(paths []string) error {
	_, err := f.run("rm -rf -- " + quoteAll(paths))
	return err
}

func (f *sshFS) ReadHead(p string, max int) ([]byte, error) {
	out, err := f.run("head -c " + strconv.Itoa(max) + " -- " + shellQuote(p))
	return []byte(out), err
}

func (f *sshFS) DiskUsage(paths []string) (int64, error) {
	out, err := f.run("du -sb -- " + quoteAll(paths) + " 2>/dev/null | awk '{s+=$1} END {print s+0}'")
	if err != nil && strings.TrimSpace(out) == "" {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

// ---------------------------------------------------------------------------
// This computer
// ---------------------------------------------------------------------------

type localFS struct{ name string }

// real turns a slash path into this computer's path (/C/Users -> C:\Users).
func (localFS) real(p string) string {
	p = path.Clean("/" + p)
	if runtime.GOOS != "windows" {
		return p
	}
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)
	if parts[0] == "" {
		return ""
	}
	r := parts[0] + `:\`
	if len(parts) == 2 {
		r += filepath.FromSlash(parts[1])
	}
	return r
}

// virt is the opposite of real.
func (localFS) virt(p string) string {
	if runtime.GOOS != "windows" {
		return filepath.ToSlash(p)
	}
	if v := filepath.VolumeName(p); len(v) == 2 && v[1] == ':' {
		return path.Clean("/" + strings.ToUpper(v[:1]) + "/" + filepath.ToSlash(p[2:]))
	}
	return filepath.ToSlash(p)
}

func (l localFS) Label() string {
	if l.name != "" {
		return l.name
	}
	return "This computer"
}
func (localFS) Local() bool { return true }
func (localFS) Close()      {}

func (l localFS) Home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return l.virt(h)
	}
	return "/"
}

func (l localFS) List(dir string) ([]fsEntry, error) {
	r := l.real(dir)
	if r == "" { // Windows: the drives
		var out []fsEntry
		for c := 'A'; c <= 'Z'; c++ {
			if _, err := os.Stat(string(c) + `:\`); err == nil {
				out = append(out, fsEntry{name: string(c), dir: true})
			}
		}
		return out, nil
	}
	items, err := os.ReadDir(r)
	if err != nil {
		return nil, err
	}
	out := make([]fsEntry, 0, len(items))
	for _, it := range items {
		e := fsEntry{name: it.Name(), dir: it.IsDir(), link: it.Type()&fs.ModeSymlink != 0}
		if info, err := it.Info(); err == nil {
			e.size, e.mod = info.Size(), info.ModTime().Format("2006-01-02 15:04")
		}
		if e.link { // follow, like the node listing does
			if st, err := os.Stat(filepath.Join(r, it.Name())); err == nil {
				e.dir = st.IsDir()
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func (l localFS) find(root string, match func(name string) bool, limit int) ([]fsHit, error) {
	var hits []fsHit
	deadline := time.Now().Add(20 * time.Second)
	stop := errors.New("stop")
	err := filepath.WalkDir(l.real(root), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if len(hits) >= limit || time.Now().After(deadline) {
			return stop
		}
		if match(d.Name()) {
			hits = append(hits, fsHit{path: l.virt(p), dir: d.IsDir()})
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) && len(hits) == 0 {
		return nil, err
	}
	return hits, nil
}

func (l localFS) Find(dir, name string) ([]fsHit, error) {
	n := strings.ToLower(name)
	return l.find(dir, func(s string) bool { return strings.Contains(strings.ToLower(s), n) }, 300)
}

func (l localFS) FindCompose() ([]fsHit, error) {
	return l.find(l.Home(), isComposeName, 200)
}

func (l localFS) Mkdir(p string) error { return os.MkdirAll(l.real(p), 0o755) }

func (l localFS) Rename(from, to string) error {
	if _, err := os.Lstat(l.real(to)); err == nil {
		return errors.New(path.Base(to) + " already exists")
	}
	return os.Rename(l.real(from), l.real(to))
}

func (l localFS) Remove(paths []string) error {
	for _, p := range paths {
		if err := os.RemoveAll(l.real(p)); err != nil {
			return err
		}
	}
	return nil
}

func (l localFS) ReadHead(p string, max int) ([]byte, error) {
	f, err := os.Open(l.real(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, int64(max)))
}

func (l localFS) DiskUsage(paths []string) (int64, error) {
	var total int64
	for _, p := range paths {
		_ = filepath.WalkDir(l.real(p), func(_ string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if info, err := d.Info(); err == nil {
					total += info.Size()
				}
			}
			return nil
		})
	}
	return total, nil
}

// ---------------------------------------------------------------------------
// Demo: an in-memory tree per node (changes last until KubesTUI closes)
// ---------------------------------------------------------------------------

type memFS struct {
	label string
	home  string
	mu    sync.Mutex
	tree  map[string][]fsEntry
}

var (
	demoFSMu  sync.Mutex
	demoFSAll = map[string]*memFS{}
)

// demoNodeFS returns the demo file system of a node (one per name).
func demoNodeFS(label string) *memFS {
	demoFSMu.Lock()
	defer demoFSMu.Unlock()
	if m := demoFSAll[label]; m != nil {
		return m
	}
	m := &memFS{label: label, home: "/home/admin", tree: map[string][]fsEntry{}}
	for d, entries := range demoTree {
		m.tree[d] = append([]fsEntry(nil), entries...)
	}
	demoFSAll[label] = m
	return m
}

func (m *memFS) Label() string { return m.label }
func (m *memFS) Local() bool   { return false }
func (m *memFS) Home() string  { return m.home }
func (m *memFS) Close()        {}

func (m *memFS) List(dir string) ([]fsEntry, error) {
	time.Sleep(80 * time.Millisecond)
	m.mu.Lock()
	defer m.mu.Unlock()
	dir = path.Clean("/" + dir)
	if _, ok := m.tree[dir]; !ok && dir != "/" {
		return nil, fmt.Errorf("%s: no such folder", dir)
	}
	out := append([]fsEntry(nil), m.tree[dir]...)
	for i := range out {
		if out[i].mod == "" {
			out[i].mod = "2026-09-30 18:42"
		}
	}
	return out, nil
}

func (m *memFS) Find(dir, name string) ([]fsHit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []fsHit
	for d, entries := range m.tree {
		if d != dir && !strings.HasPrefix(d, strings.TrimSuffix(dir, "/")+"/") {
			continue
		}
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.name), strings.ToLower(name)) {
				out = append(out, fsHit{path: path.Join(d, e.name), dir: e.dir})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func (m *memFS) FindCompose() ([]fsHit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []fsHit
	for d, entries := range m.tree {
		for _, e := range entries {
			if isComposeName(e.name) {
				out = append(out, fsHit{path: path.Join(d, e.name)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func (m *memFS) entry(p string) (int, string) {
	dir := path.Dir(p)
	for i, e := range m.tree[dir] {
		if e.name == path.Base(p) {
			return i, dir
		}
	}
	return -1, dir
}

// add puts an entry in dir (replacing one with the same name).
func (m *memFS) add(dir string, e fsEntry) {
	if i, _ := m.entry(path.Join(dir, e.name)); i >= 0 {
		m.tree[dir][i] = e
	} else {
		m.tree[dir] = append(m.tree[dir], e)
	}
	if e.dir {
		if _, ok := m.tree[path.Join(dir, e.name)]; !ok {
			m.tree[path.Join(dir, e.name)] = nil
		}
	}
}

func (m *memFS) Mkdir(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p = path.Clean(p)
	for d := p; d != "/"; d = path.Dir(d) {
		if i, _ := m.entry(d); i < 0 {
			m.add(path.Dir(d), fsEntry{name: path.Base(d), dir: true, size: 4096, mod: time.Now().Format("2006-01-02 15:04")})
		}
	}
	return nil
}

func (m *memFS) Rename(from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i, _ := m.entry(to); i >= 0 {
		return errors.New(path.Base(to) + " already exists")
	}
	i, dir := m.entry(from)
	if i < 0 {
		return errors.New(path.Base(from) + " not found")
	}
	e := m.tree[dir][i]
	m.tree[dir] = append(m.tree[dir][:i], m.tree[dir][i+1:]...)
	e.name = path.Base(to)
	m.add(path.Dir(to), e)
	m.moveTree(from, to)
	return nil
}

// moveTree renames a folder's subtree.
func (m *memFS) moveTree(from, to string) {
	for d, entries := range m.tree {
		if d == from || strings.HasPrefix(d, from+"/") {
			delete(m.tree, d)
			m.tree[to+strings.TrimPrefix(d, from)] = entries
		}
	}
}

func (m *memFS) Remove(paths []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range paths {
		if i, dir := m.entry(p); i >= 0 {
			m.tree[dir] = append(m.tree[dir][:i], m.tree[dir][i+1:]...)
		}
		for d := range m.tree {
			if d == p || strings.HasPrefix(d, p+"/") {
				delete(m.tree, d)
			}
		}
	}
	return nil
}

// copyFrom copies items from another demo node's tree (or this one).
func (m *memFS) copyFrom(src *memFS, paths []string, dest string) {
	src.mu.Lock()
	type item struct {
		dir   string
		e     fsEntry
		trees map[string][]fsEntry
	}
	var items []item
	for _, p := range paths {
		i, dir := src.entry(p)
		if i < 0 {
			continue
		}
		it := item{dir: dir, e: src.tree[dir][i], trees: map[string][]fsEntry{}}
		for d, entries := range src.tree {
			if d == p || strings.HasPrefix(d, p+"/") {
				it.trees[path.Join(dest, path.Base(p))+strings.TrimPrefix(d, p)] = append([]fsEntry(nil), entries...)
			}
		}
		items = append(items, it)
	}
	src.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, it := range items {
		m.add(dest, it.e)
		for d, entries := range it.trees {
			m.tree[d] = entries
		}
	}
}

func (m *memFS) ReadHead(p string, max int) ([]byte, error) {
	text := "# " + path.Base(p) + " on " + m.label + " (demo)\n\nThis is a simulated file. In a real cluster you see\nthe first part of the file here.\n"
	if isComposeName(path.Base(p)) {
		text = "services:\n  app:\n    image: lscr.io/linuxserver/jellyfin:latest\n    ports:\n      - 8096:8096\n    volumes:\n      - ./config:/config\n      - /mnt/hdd/media:/media\n"
	}
	return []byte(text), nil
}

func (m *memFS) DiskUsage(paths []string) (int64, error) {
	return int64(len(paths)) * 734 << 20, nil
}

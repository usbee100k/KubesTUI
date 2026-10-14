package main

// Copying and moving between the Files manager's two panes. The fastest
// way for each pair:
//
//   this computer -> node     tar over SSH (transfer.go)
//   node -> this computer     tar over SSH, unpacked here
//   within one node           cp -a / mv on the node
//   node A -> node B          two Kubernetes Jobs: a receiver on B
//                             (nc -l | tar -x) and a sender on A
//                             (tar -c | nc), so the data goes straight
//                             between the nodes, never through here
//   other hosts               relayed through here
//
// A move is a copy, then the source is deleted only if the copy worked.

import (
	"archive/tar"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"go.yaml.in/yaml/v3"
)

// kubeRunner runs a shell script on a machine with cluster access; "$K"
// in the script is kubectl.
type kubeRunner func(script, stdin string) (string, error)

// copyPlan is one copy or move.
type copyPlan struct {
	src, dst fileSys
	srcDir   string
	names    []string
	dest     string
	move     bool
	kube     kubeRunner             // nil: node-to-node copies are relayed
	isNode   func(name string) bool // a cluster node (Jobs can run there)
	log      func(string)
}

func (c *copyPlan) srcPaths() []string {
	out := make([]string, len(c.names))
	for i, n := range c.names {
		out[i] = path.Join(c.srcDir, n)
	}
	return out
}

func (c *copyPlan) dstPaths() []string {
	out := make([]string, len(c.names))
	for i, n := range c.names {
		out[i] = path.Join(c.dest, n)
	}
	return out
}

func (c *copyPlan) verb() string {
	if c.move {
		return "Move"
	}
	return "Copy"
}

// script runs the plan in the built-in terminal.
func (c *copyPlan) script() func(d *demoTerm) int {
	return func(d *demoTerm) int {
		d.Printf("\n%s %d item(s)\n  from %s:%s\n  to   %s:%s\n\n", c.verb(), len(c.names), c.src.Label(), c.srcDir, c.dst.Label(), c.dest)
		start := time.Now()
		err := c.run(d)
		if err != nil {
			d.Print("\n" + cFail + err.Error() + "\n")
			c.log(fmt.Sprintf("%s FAILED %s:%s -> %s:%s %v: %v", strings.ToUpper(c.verb()), c.src.Label(), c.srcDir, c.dst.Label(), c.dest, c.names, err))
			return 1
		}
		if c.move {
			if err := c.src.Remove(c.srcPaths()); err != nil {
				d.Print("\n" + cWarn + "Copied, but removing the originals failed: " + err.Error() + "\n")
				c.log(fmt.Sprintf("MOVE copied, source not removed %s:%v: %v", c.src.Label(), c.srcPaths(), err))
				return 1
			}
		}
		c.log(fmt.Sprintf("%s %s:%s -> %s:%s %v", strings.ToUpper(c.verb()), c.src.Label(), c.srcDir, c.dst.Label(), c.dest, c.names))
		d.Printf("\n"+cOK+"%s done in %s.\n", map[bool]string{true: "Move", false: "Copy"}[c.move], time.Since(start).Round(time.Second))
		return 0
	}
}

func (c *copyPlan) run(d *demoTerm) error {
	sm, sDemo := c.src.(*memFS)
	dm, dDemo := c.dst.(*memFS)
	ss, sSSH := c.src.(*sshFS)
	ds, dSSH := c.dst.(*sshFS)
	switch {
	case sDemo && dDemo:
		return c.demoCopy(d, sm, dm)
	case isVolume(c.src) || isVolume(c.dst):
		return c.streamCopy(d)
	case c.src.Local() && c.dst.Local():
		return c.localToLocal(d)
	case c.src.Local() && dSSH:
		return c.localToNode(d, ds)
	case sSSH && c.dst.Local():
		return c.nodeToLocal(d, ss)
	case sSSH && dSSH && ss.label == ds.label:
		return c.withinNode(d, ss)
	case sSSH && dSSH:
		if c.kube != nil && c.isNode != nil && c.isNode(ss.label) && c.isNode(ds.label) {
			return c.nodeToNode(d, ss, ds)
		}
		d.Print(cWarn + "Not both cluster nodes: the files go through this computer.\n")
		return c.relay(d, ss, ds)
	}
	return errors.New("can't copy between these locations")
}

// progress prints a progress line until stop is closed.
func progress(d *demoTerm, total int64, done func() int64, stop <-chan struct{}) {
	start := time.Now()
	show := func() {
		n := done()
		if total > 0 {
			n = min(n, total) // tar's own headers count too
		}
		pct := ""
		if total > 0 {
			pct = fmt.Sprintf("%5.1f%%  ", min(float64(n)*100/float64(total), 100))
		}
		rate := float64(n) / max(time.Since(start).Seconds(), 0.001)
		d.raw(fmt.Sprintf("\r  %s%s of %s  %s/s     ", pct, fmtBytes(n), fmtBytes(total), fmtBytes(int64(rate))))
	}
	for {
		select {
		case <-stop:
			show()
			d.Print("\n")
			return
		case <-time.After(time.Second):
			show()
		}
	}
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

func (c *copyPlan) demoCopy(d *demoTerm, src, dst *memFS) error {
	how := "tar over SSH"
	switch {
	case strings.HasPrefix(dst.label, "vol ") || strings.HasPrefix(src.label, "vol "):
		how = "a tar stream through the volume's helper pod"
	case src == dst:
		how = "cp -a on " + src.label
	case c.isNode != nil && c.isNode(src.label) && c.isNode(dst.label):
		how = "Kubernetes Jobs: receiver on " + dst.label + ", sender on " + src.label
	}
	d.Print(cInfo + "Using " + how + "\n")
	for i := 0; i <= 20; i++ {
		pct := float64(i) * 5
		d.raw(fmt.Sprintf("\r  %5.1f%%  %s of 1.4 GiB  96.0 MiB/s     ", pct, fmtBytes(int64(pct/100*1.4*(1<<30)))))
		if !d.Sleep(120 * time.Millisecond) {
			return errors.New("stopped")
		}
	}
	d.Print("\n")
	dst.copyFrom(src, c.srcPaths(), c.dest)
	if strings.HasPrefix(dst.label, "vol ") {
		ns, _, _ := strings.Cut(strings.TrimPrefix(dst.label, "vol "), "/")
		d.Print(cOK + "Owner set to 1000:1000 (the same as " + c.dest + "), so the app can use them.\n")
		d.Printf("\ndeployment/%s uses this volume. Restart it now so it picks up the files? (y/N): ", ns)
		if a, ok := d.ReadLine(true); ok && strings.HasPrefix(strings.ToLower(strings.TrimSpace(a)), "y") {
			d.Print(cOK + "Restarted deployment/" + ns + ".\n")
		} else {
			d.Print("Not restarted. Later: kubectl -n " + ns + " rollout restart deployment/" + ns + "\n")
		}
	}
	return nil
}

func (c *copyPlan) localToLocal(d *demoTerm) error {
	l := localFS{}
	total, _ := l.DiskUsage(c.srcPaths())
	var real []string
	for _, p := range c.srcPaths() {
		real = append(real, l.real(p))
	}
	pr, pw := io.Pipe()
	var sent atomic.Int64
	var skipped []string
	go func() {
		_, sk, err := writeTar(pw, real, &sent)
		skipped = sk
		pw.CloseWithError(err)
	}()
	stop := make(chan struct{})
	go progress(d, total, sent.Load, stop)
	err := extractTar(l.real(c.dest), pr)
	close(stop)
	time.Sleep(50 * time.Millisecond)
	for _, s := range skipped {
		d.Print("  " + cWarn + s + "\n")
	}
	return err
}

func (c *copyPlan) localToNode(d *demoTerm, dst *sshFS) error {
	l := localFS{}
	var real []string
	for _, p := range c.srcPaths() {
		real = append(real, l.real(p))
	}
	job := transferJob{paths: real, node: dst.node, dest: c.dest, keys: dst.keys}
	if transferScript(job)(d) != 0 {
		return errors.New("the transfer didn't finish")
	}
	return nil
}

func (c *copyPlan) nodeToLocal(d *demoTerm, src *sshFS) error {
	total, _ := src.DiskUsage(c.srcPaths())
	session, err := src.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	out, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	session.Stderr = &stderr
	cmd := "tar -c -C " + shellQuote(c.srcDir) + " -- " + quoteAll(c.names)
	if src.sudo == 1 {
		cmd = "sudo -n " + cmd
	}
	if err := session.Start(cmd); err != nil {
		return err
	}
	var got atomic.Int64
	stop := make(chan struct{})
	go progress(d, total, got.Load, stop)
	in := io.TeeReader(out, countingWriter{io.Discard, &got})
	err = extractTar(localFS{}.real(c.dest), in)
	_, _ = io.Copy(io.Discard, in) // tar's padding after the end marker
	werr := session.Wait()
	close(stop)
	time.Sleep(50 * time.Millisecond)
	if err != nil {
		return err
	}
	if werr != nil {
		return fmt.Errorf("%v %s", werr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (c *copyPlan) withinNode(d *demoTerm, n *sshFS) error {
	d.Print(cInfo + "Copying on " + n.label + " itself (nothing goes over the network)\n")
	total, _ := n.DiskUsage(c.srcPaths())
	stop := make(chan struct{})
	var done atomic.Int64
	go func() { // the destination's size, for the progress line
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Second):
				if b, err := n.DiskUsage(c.dstPaths()); err == nil {
					done.Store(b)
				}
			}
		}
	}()
	go progress(d, total, done.Load, stop)
	cmd := "mkdir -p -- " + shellQuote(c.dest) + " && "
	if c.move {
		cmd += "mv -- " + quoteAll(c.srcPaths()) + " " + shellQuote(c.dest+"/")
	} else {
		cmd += "cp -a -- " + quoteAll(c.srcPaths()) + " " + shellQuote(c.dest+"/")
	}
	_, err := n.run(cmd) // after mv, removing the originals finds nothing left
	done.Store(total)
	close(stop)
	time.Sleep(50 * time.Millisecond)
	return err
}

// relay pipes node A's tar into node B through this computer.
func (c *copyPlan) relay(d *demoTerm, a, b *sshFS) error {
	total, _ := a.DiskUsage(c.srcPaths())
	sa, err := a.client.NewSession()
	if err != nil {
		return err
	}
	defer sa.Close()
	sb, err := b.client.NewSession()
	if err != nil {
		return err
	}
	defer sb.Close()
	out, _ := sa.StdoutPipe()
	in, _ := sb.StdinPipe()
	var ea, eb strings.Builder
	sa.Stderr, sb.Stderr = &ea, &eb
	if err := sa.Start("tar -c -C " + shellQuote(c.srcDir) + " -- " + quoteAll(c.names)); err != nil {
		return err
	}
	if err := sb.Start("mkdir -p -- " + shellQuote(c.dest) + " && tar -x -C " + shellQuote(c.dest)); err != nil {
		return err
	}
	var sent atomic.Int64
	stop := make(chan struct{})
	go progress(d, total, sent.Load, stop)
	_, cerr := io.Copy(countingWriter{in, &sent}, out)
	in.Close()
	errA, errB := sa.Wait(), sb.Wait()
	close(stop)
	time.Sleep(50 * time.Millisecond)
	for _, e := range []struct {
		err error
		msg string
	}{{cerr, ""}, {errA, ea.String()}, {errB, eb.String()}} {
		if e.err != nil {
			return fmt.Errorf("%v %s", e.err, strings.TrimSpace(e.msg))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Into and out of Longhorn volumes: a tar stream from one end to the other
// ---------------------------------------------------------------------------

func isVolume(f fileSys) bool {
	s, ok := f.(*sshFS)
	return ok && s.vol != nil
}

// tarOut streams dir's names as tar from f.
func tarOut(f fileSys, dir string, names []string) (io.Reader, func() error, error) {
	switch fs := f.(type) {
	case localFS:
		var real []string
		for _, n := range names {
			real = append(real, fs.real(path.Join(dir, n)))
		}
		pr, pw := io.Pipe()
		errc := make(chan error, 1)
		go func() {
			_, _, err := writeTar(pw, real, new(atomic.Int64))
			pw.CloseWithError(err)
			errc <- err
		}()
		return pr, func() error { return <-errc }, nil
	case *sshFS:
		cmd := "tar -c -C " + shellQuote(dir) + " -- " + quoteAll(names)
		if fs.vol != nil {
			pr, pw := io.Pipe()
			errc := make(chan error, 1)
			go func() {
				err := fs.stream(volExec(fs)+cmd, nil, pw)
				pw.CloseWithError(err)
				errc <- err
			}()
			return pr, func() error { return <-errc }, nil
		}
		if fs.sudo == 1 {
			cmd = "sudo -n " + cmd
		}
		session, err := fs.client.NewSession()
		if err != nil {
			return nil, nil, err
		}
		out, _ := session.StdoutPipe()
		var stderr strings.Builder
		session.Stderr = &stderr
		if err := session.Start(cmd); err != nil {
			session.Close()
			return nil, nil, err
		}
		return out, func() error {
			defer session.Close()
			if err := session.Wait(); err != nil {
				return fmt.Errorf("%v %s", err, strings.TrimSpace(stderr.String()))
			}
			return nil
		}, nil
	}
	return nil, nil, errors.New("can't read from " + f.Label())
}

// tarIn unpacks a tar stream into dest on f.
func tarIn(f fileSys, dest string) (io.WriteCloser, func() error, error) {
	switch fs := f.(type) {
	case localFS:
		pr, pw := io.Pipe()
		errc := make(chan error, 1)
		go func() {
			err := extractTar(fs.real(dest), pr)
			if err == nil {
				_, _ = io.Copy(io.Discard, pr) // tar pads its stream past the end marker
			}
			pr.CloseWithError(err)
			errc <- err
		}()
		return pw, func() error { return <-errc }, nil
	case *sshFS:
		cmd := "mkdir -p -- " + shellQuote(dest) + " && tar -x -C " + shellQuote(dest)
		if fs.vol != nil {
			pr, pw := io.Pipe()
			errc := make(chan error, 1)
			go func() {
				err := fs.stream(volExec(fs)+"sh -c "+shellQuote(cmd), pr, io.Discard)
				pr.CloseWithError(err)
				errc <- err
			}()
			return pw, func() error { return <-errc }, nil
		}
		if fs.sudo == 1 {
			cmd = "sudo -n sh -c " + shellQuote(cmd)
		}
		session, err := fs.client.NewSession()
		if err != nil {
			return nil, nil, err
		}
		in, _ := session.StdinPipe()
		var stderr strings.Builder
		session.Stderr = &stderr
		if err := session.Start(cmd); err != nil {
			session.Close()
			return nil, nil, err
		}
		return in, func() error {
			defer session.Close()
			if err := session.Wait(); err != nil {
				return fmt.Errorf("%v %s", err, strings.TrimSpace(stderr.String()))
			}
			return nil
		}, nil
	}
	return nil, nil, errors.New("can't write to " + f.Label())
}

// streamCopy copies with a tar stream from the source to the destination
// (used when one end is a Longhorn volume). Files copied into a volume
// get the owner of the folder they land in, so the app can use them.
func (c *copyPlan) streamCopy(d *demoTerm) error {
	via := ""
	if isVolume(c.dst) || isVolume(c.src) {
		via = " (through the volume's helper pod)"
	}
	d.Print(cInfo + "Streaming " + c.src.Label() + " → " + c.dst.Label() + via + "\n")
	total, _ := c.src.DiskUsage(c.srcPaths())
	r, waitOut, err := tarOut(c.src, c.srcDir, c.names)
	if err != nil {
		return err
	}
	w, waitIn, err := tarIn(c.dst, c.dest)
	if err != nil {
		return err
	}
	var sent atomic.Int64
	stop := make(chan struct{})
	go progress(d, total, sent.Load, stop)
	_, cerr := io.Copy(countingWriter{w, &sent}, r)
	w.Close()
	errOut, errIn := waitOut(), waitIn()
	close(stop)
	time.Sleep(50 * time.Millisecond)
	for _, e := range []error{errIn, errOut, cerr} {
		if e != nil {
			return e
		}
	}
	if dst, ok := c.dst.(*sshFS); ok && dst.vol != nil {
		out, err := dst.run("o=$(stat -c %u:%g " + shellQuote(c.dest) + ") && chown -R \"$o\" -- " + quoteAll(c.dstPaths()) + " && echo \"$o\"")
		if err == nil {
			d.Print(cOK + "Owner set to " + strings.TrimSpace(out) + " (the same as " + c.dest + "), so the app can use them.\n")
		} else {
			d.Print(cWarn + "Couldn't set the owner: " + err.Error() + "\n")
		}
		restartUsers(d, c.kube, dst.vol)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Node to node with Kubernetes Jobs
// ---------------------------------------------------------------------------

const copyNamespace = "kubestui"

func copyJob(name, id, role, node string, cmd []string, vol obj, mount obj) obj {
	return obj{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": obj{"name": name, "namespace": copyNamespace,
			"labels": obj{"app.kubernetes.io/managed-by": "kubestui", "kubestui-copy": id}},
		"spec": obj{
			"backoffLimit":            0,
			"ttlSecondsAfterFinished": 600,
			"activeDeadlineSeconds":   86400,
			"template": obj{
				"metadata": obj{"labels": obj{"kubestui-copy": id, "role": role}},
				"spec": obj{
					"nodeName":      node,
					"restartPolicy": "Never",
					"tolerations":   []obj{{"operator": "Exists"}},
					"containers": []obj{{
						"name":         role,
						"image":        "busybox:1.37",
						"command":      cmd,
						"volumeMounts": []obj{mount},
					}},
					"volumes": []obj{vol},
				},
			},
		},
	}
}

func (c *copyPlan) nodeToNode(d *demoTerm, a, b *sshFS) error {
	k := c.kube
	idb := make([]byte, 4)
	_, _ = rand.Read(idb)
	id := hex.EncodeToString(idb)
	recv, send := "kubestui-copy-"+id+"-recv", "kubestui-copy-"+id+"-send"

	d.Print(cInfo + "Straight from " + a.label + " to " + b.label + " with two Kubernetes Jobs\n")
	total, _ := a.DiskUsage(c.srcPaths())

	cleanup := func() {
		_, _ = k("$K -n "+copyNamespace+" delete job "+recv+" "+send+" --ignore-not-found --wait=false >/dev/null 2>&1", "")
	}
	defer cleanup()

	if _, err := k("$K create namespace "+copyNamespace+" --dry-run=client -o yaml | $K apply -f - >/dev/null", ""); err != nil {
		return fmt.Errorf("cluster access: %v", err)
	}

	// Receiver on B: unpacks what arrives into the destination folder.
	r := copyJob(recv, id, "recv", b.label,
		[]string{"sh", "-c", "nc -l -p 9000 | tar -x -C /dest && echo RECEIVED"},
		obj{"name": "dest", "hostPath": obj{"path": c.dest, "type": "DirectoryOrCreate"}},
		obj{"name": "dest", "mountPath": "/dest"})
	if err := c.apply(r); err != nil {
		return err
	}
	d.Print("  receiver starting on " + b.label + "…\n")
	ip := ""
	for i := 0; i < 90 && ip == ""; i++ {
		out, _ := k("$K -n "+copyNamespace+" get pods -l kubestui-copy="+id+",role=recv -o jsonpath='{.items[0].status.phase} {.items[0].status.podIP}'", "")
		if phase, addr, _ := strings.Cut(strings.TrimSpace(out), " "); phase == "Running" && addr != "" {
			ip = addr
		} else if phase == "Failed" {
			break
		}
		if !d.Sleep(2 * time.Second) {
			return errors.New("stopped")
		}
	}
	if ip == "" {
		why, _ := k("$K -n "+copyNamespace+" describe pods -l kubestui-copy="+id+",role=recv | tail -n 8", "")
		return errors.New("the receiver on " + b.label + " didn't start:\n" + why)
	}

	// Sender on A: the items as a tar stream to the receiver's pod IP
	// (retried briefly while the receiver opens its port).
	args := []string{"sh", "-c", `for i in $(seq 15); do tar -c -C /src -- "$@" | nc -w 5 "$RECV" 9000 && exit 0; sleep 2; done; exit 1`, "sh"}
	for _, n := range c.names {
		args = append(args, "./"+n)
	}
	s := copyJob(send, id, "send", a.label, args,
		obj{"name": "src", "hostPath": obj{"path": c.srcDir, "type": "Directory"}},
		obj{"name": "src", "mountPath": "/src", "readOnly": true})
	cont := s["spec"].(obj)["template"].(obj)["spec"].(obj)["containers"].([]obj)[0]
	cont["env"] = []obj{{"name": "RECV", "value": ip}}
	if err := c.apply(s); err != nil {
		return err
	}
	d.Print("  sender started on " + a.label + "; copying " + fmtBytes(total) + "\n")

	var done atomic.Int64
	stop := make(chan struct{})
	go progress(d, total, done.Load, stop)
	defer func() { close(stop); time.Sleep(50 * time.Millisecond) }()

	status := func(job string) string {
		out, _ := k("$K -n "+copyNamespace+" get job "+job+" -o jsonpath='{.status.succeeded}/{.status.failed}'", "")
		return strings.TrimSpace(out)
	}
	for {
		if !d.Sleep(2 * time.Second) {
			return errors.New("stopped (the Jobs are removed)")
		}
		if n, err := b.DiskUsage(c.dstPaths()); err == nil {
			done.Store(n)
		}
		sr, rr := status(send), status(recv)
		switch {
		case strings.HasSuffix(sr, "/1") || strings.HasSuffix(rr, "/1"):
			logs, _ := k("$K -n "+copyNamespace+" logs job/"+send+" --tail=5; $K -n "+copyNamespace+" logs job/"+recv+" --tail=5", "")
			return errors.New("the copy failed:\n" + strings.TrimSpace(logs))
		case strings.HasPrefix(sr, "1/") && strings.HasPrefix(rr, "1/"):
			done.Store(max(done.Load(), total))
			return nil
		}
	}
}

func (c *copyPlan) apply(o obj) error {
	data, err := yaml.Marshal(o)
	if err != nil {
		return err
	}
	if out, err := c.kube("$K apply -f - >/dev/null", string(data)); err != nil {
		return fmt.Errorf("creating the copy Job: %v %s", err, out)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Unpacking here
// ---------------------------------------------------------------------------

// extractTar unpacks a tar stream into dir (nothing outside it).
func extractTar(dir string, r io.Reader) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if name == "." || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) || filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
			continue
		}
		target := filepath.Join(dir, name)
		mode := os.FileMode(hdr.Mode).Perm()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, max(mode, 0o600))
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, hdr.Size))
			f.Close()
			if err != nil {
				return err
			}
			_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
		case tar.TypeSymlink:
			if runtime.GOOS == "windows" {
				continue // needs admin rights on Windows
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		}
	}
}

package main

// "Transfer Files to a Node": copy files or folders from this computer to
// any node over SSH. Drag them from the file manager into the box (the
// terminal pastes their paths), pick the node, and the folder there
// (default /home/<user>/). The files travel as a tar stream over the
// cluster's SSH key login, with a progress line; a folder that needs root
// can be written with sudo.

import (
	"archive/tar"
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// splitDropped splits what a drag-and-drop pasted: one or more paths,
// each possibly in quotes. Windows Terminal quotes paths with spaces;
// PowerShell (and VS Code's terminal) pastes & 'C:\path' (its "run this"
// operator; a quote inside the name is doubled).
func splitDropped(s string) []string {
	var out []string
	s = strings.TrimSpace(s)
	for s != "" {
		var p string
		switch q := s[0]; {
		case q == '&' && (len(s) == 1 || s[1] == ' ' || s[1] == '\t'):
			s = strings.TrimSpace(s[1:]) // PowerShell's call operator
			continue
		case q == '\'':
			// Single quotes: '' is a literal ' (PowerShell).
			var b strings.Builder
			i := 1
			for ; i < len(s); i++ {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						b.WriteByte('\'')
						i++
						continue
					}
					break
				}
				b.WriteByte(s[i])
			}
			p, s = b.String(), s[min(i+1, len(s)):]
		case q == '"':
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				p, s = s[1:], ""
			} else {
				p, s = s[1:end+1], s[end+2:]
			}
		case fileExists(s):
			p, s = s, "" // one unquoted path that contains spaces
		default:
			end := strings.IndexAny(s, " \t")
			if end < 0 {
				p, s = s, ""
			} else {
				p, s = s[:end], s[end:]
			}
		}
		if p = strings.TrimSpace(p); p != "" {
			if strings.HasPrefix(p, "~") {
				if home, err := os.UserHomeDir(); err == nil {
					p = filepath.Join(home, strings.TrimPrefix(p, "~"))
				}
			}
			out = append(out, p)
		}
		s = strings.TrimSpace(s)
	}
	return out
}

// What one item in a transfer is sent as.
const (
	itemSkip = iota
	itemDir
	itemFile
	itemLink
)

// transferItem decides how to send p. Anything with readable contents is
// sent as a file, whatever its type: on Windows that includes OneDrive's
// online-only files (reparse points Go reports as irregular, read on
// demand) and links to files (the target's contents; a Windows link target
// means nothing on Linux). why says why an item is skipped.
func transferItem(p string, d fs.DirEntry) (kind int, info fs.FileInfo, why string) {
	switch t := d.Type(); {
	case d.IsDir():
		info, err := d.Info()
		if err != nil {
			return itemSkip, nil, err.Error()
		}
		return itemDir, info, ""
	case t.IsRegular():
		info, err := d.Info()
		if err != nil {
			return itemSkip, nil, err.Error()
		}
		return itemFile, info, ""
	case t&fs.ModeSymlink != 0 && runtime.GOOS != "windows":
		info, err := d.Info()
		if err != nil {
			return itemSkip, nil, err.Error()
		}
		return itemLink, info, ""
	case t&(fs.ModeDevice|fs.ModeCharDevice|fs.ModeNamedPipe|fs.ModeSocket) != 0:
		return itemSkip, nil, "a device, pipe or socket, not a file"
	}
	// Links on Windows, OneDrive placeholders, other irregular entries:
	// follow to what they point at.
	info, err := os.Stat(p)
	switch {
	case err != nil:
		return itemSkip, nil, err.Error()
	case info.Mode().IsRegular():
		return itemFile, info, ""
	case info.IsDir():
		return itemSkip, nil, "a link to a folder (copy the folder itself)"
	}
	return itemSkip, nil, "not a file or folder"
}

// walkTransfer calls fn for every item under the paths, with its name in
// the archive (each top-level item keeps its own name).
func walkTransfer(paths []string, fn func(p, name string, kind int, info fs.FileInfo, why string) error) error {
	for _, root := range paths {
		root = filepath.Clean(root)
		base := filepath.Dir(root)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			rel, rerr := filepath.Rel(base, p)
			if rerr != nil {
				return rerr
			}
			name := filepath.ToSlash(rel)
			if err != nil {
				// An unreadable folder: skip it, keep going.
				if p == root {
					return err
				}
				if ferr := fn(p, name, itemSkip, nil, err.Error()); ferr != nil {
					return ferr
				}
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			kind, info, why := transferItem(p, d)
			return fn(p, name, kind, info, why)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// transferSize counts the files and bytes under the given paths.
func transferSize(paths []string) (files int, bytes int64, err error) {
	err = walkTransfer(paths, func(_, _ string, kind int, info fs.FileInfo, _ string) error {
		if kind == itemFile {
			files++
			bytes += info.Size()
		}
		return nil
	})
	return
}

// countingWriter counts what passes through, for the progress line.
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n.Add(int64(n))
	return n, err
}

// writeTar streams the paths as a tar archive (PAX: any size, any name).
// Items that can't be sent (unreadable, locked by another program,
// devices) are skipped and returned, so the rest still arrives.
func writeTar(w io.Writer, paths []string, sent *atomic.Int64) (copied int, skipped []string, err error) {
	tw := tar.NewWriter(w)
	err = walkTransfer(paths, func(p, name string, kind int, info fs.FileInfo, why string) error {
		hdr := &tar.Header{Name: name, Format: tar.FormatPAX}
		if info != nil {
			hdr.ModTime = info.ModTime()
		}
		switch kind {
		case itemSkip:
			skipped = append(skipped, name+": "+why)
			return nil
		case itemDir:
			hdr.Typeflag, hdr.Name, hdr.Mode = tar.TypeDir, name+"/", 0o755
			return tw.WriteHeader(hdr)
		case itemLink:
			target, err := os.Readlink(p)
			if err != nil {
				skipped = append(skipped, name+": "+err.Error())
				return nil
			}
			hdr.Typeflag, hdr.Linkname, hdr.Mode = tar.TypeSymlink, target, 0o777
			return tw.WriteHeader(hdr)
		}

		// A file. Open it first: one that can't be read (in use by
		// another program) is skipped before anything is written.
		f, err := os.Open(p)
		if err != nil {
			skipped = append(skipped, name+": "+err.Error())
			return nil
		}
		defer f.Close()
		hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeReg, info.Size(), 0o644
		// Keep scripts runnable (Windows has no execute bit to copy).
		if runtime.GOOS != "windows" && info.Mode()&0o111 != 0 {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		// Exactly the size in the header: a file that grows while it's
		// sent is cut there, one that shrinks is padded, and either way
		// the archive stays valid.
		n, err := io.CopyN(countingWriter{tw, sent}, f, hdr.Size)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if n < hdr.Size {
			skipped = append(skipped, name+": changed while being sent (copy is incomplete)")
			if _, err := io.CopyN(tw, zeroReader{}, hdr.Size-n); err != nil {
				return err
			}
			return nil
		}
		copied++
		return nil
	})
	if err != nil {
		return copied, skipped, err
	}
	return copied, skipped, tw.Close()
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

type transferJob struct {
	paths []string
	node  hostEntry
	dest  string
	keys  []string
}

// transferScript runs the transfer in the built-in terminal.
func transferScript(job transferJob) func(d *demoTerm) int {
	return func(d *demoTerm) int {
		files, total, err := transferSize(job.paths)
		if err != nil {
			d.Print(cFail + err.Error() + "\n")
			return 1
		}
		d.Print("\n")
		for _, p := range job.paths {
			d.Print("  " + p + "\n")
		}
		d.Printf("\n%d file(s), %s  ->  %s@%s:%s\n\n", files, fmtBytes(total), job.node.User, orDefault(job.node.Name, job.node.Host), job.dest)

		d.Print(cInfo + "Connecting to " + job.node.Host + "...\n")
		client, err := dialSSH(dialTarget{Host: job.node.Host, Port: job.node.portOr22(), User: job.node.User, Keys: job.keys, Prompt: true})
		if err != nil {
			d.Print(cFail + "Could not connect: " + err.Error() + "\n")
			return 1
		}
		defer client.Close()

		dest := shellQuote(job.dest)
		// Try as the SSH user; if the folder needs root, offer sudo.
		useSudo, sudoPassword := false, ""
		if _, err := runRemote(client, "mkdir -p "+dest+" && test -w "+dest, ""); err != nil {
			d.Print(cWarn + job.dest + " isn't writable for " + job.node.User + ".\n")
			d.Print("Write it with sudo? (y/N): ")
			a, ok := d.ReadLine(true)
			if !ok {
				return d.exitCode()
			}
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(a)), "y") {
				d.Print("Cancelled. Choose a folder under /home/" + job.node.User + "/ or run it again with sudo.\n")
				return 1
			}
			useSudo = true
			// No password needed (NOPASSWD or a cached login): don't send
			// one, or it would end up in the file stream.
			if _, err := runRemote(client, "sudo -n true", ""); err != nil {
				d.Printf("[sudo] password for %s: ", job.node.User)
				if sudoPassword, ok = d.ReadLine(false); !ok {
					return d.exitCode()
				}
			}
		}

		command := "mkdir -p " + dest + " && tar -xf - -C " + dest + " --no-same-owner"
		if useSudo {
			// Files end up owned by the SSH user, as without sudo.
			command = "sh -c " + shellQuote(command+" && chown -R "+shellQuote(job.node.User)+": "+dest)
			if sudoPassword != "" {
				command = "sudo -S -p '' " + command // the password is stdin's first line, then the files
			} else {
				command = "sudo -n " + command
			}
		}

		session, err := client.NewSession()
		if err != nil {
			d.Print(cFail + err.Error() + "\n")
			return 1
		}
		defer session.Close()
		stdin, err := session.StdinPipe()
		if err != nil {
			d.Print(cFail + err.Error() + "\n")
			return 1
		}
		var stderr strings.Builder
		session.Stderr = &stderr
		if err := session.Start(command); err != nil {
			d.Print(cFail + err.Error() + "\n")
			return 1
		}

		var sent atomic.Int64
		var copied int
		var skipped []string // both set before writeErr is sent
		writeErr := make(chan error, 1)
		go func() {
			bw := bufio.NewWriterSize(stdin, 256*1024)
			if sudoPassword != "" {
				_, _ = io.WriteString(bw, sudoPassword+"\n")
			}
			n, sk, err := writeTar(bw, job.paths, &sent)
			if err == nil {
				err = bw.Flush()
			}
			stdin.Close()
			copied, skipped = n, sk
			writeErr <- err
		}()

		start := time.Now()
		progress := func() {
			n := sent.Load()
			pct := 100.0
			if total > 0 {
				pct = float64(n) * 100 / float64(total)
			}
			rate := float64(n) / max(time.Since(start).Seconds(), 0.001)
			d.raw(fmt.Sprintf("\r  %5.1f%%  %s of %s  %s/s   ", pct, fmtBytes(n), fmtBytes(total), fmtBytes(int64(rate))))
		}

		var werr error
	wait:
		for {
			select {
			case werr = <-writeErr:
				break wait
			case <-d.b.done:
				session.Close() // closed the terminal: stop
				return d.exitCode()
			case <-time.After(250 * time.Millisecond):
				progress()
			}
		}
		runErr := session.Wait()
		progress()
		d.Print("\n\n")

		if werr != nil || runErr != nil {
			msg := strings.TrimSpace(stderr.String())
			switch {
			case werr != nil && !errors.Is(werr, io.EOF):
				d.Print(cFail + "Reading the files here failed: " + werr.Error() + "\n")
			case msg != "":
				d.Print(cFail + msg + "\n")
			default:
				d.Print(cFail + fmt.Sprint(runErr) + "\n")
			}
			return 1
		}

		d.Printf(cOK+"Copied %d file(s), %s in %s.\n\n", copied, fmtBytes(sent.Load()), time.Since(start).Round(time.Second))
		if len(skipped) > 0 {
			d.Printf(cWarn+"%d item(s) not copied:\n", len(skipped))
			for i, sk := range skipped {
				if i == 20 {
					d.Printf("  … and %d more\n", len(skipped)-20)
					break
				}
				d.Print("  " + sk + "\n")
			}
			d.Print("\n")
		}
		var names []string
		for _, p := range job.paths {
			names = append(names, shellQuote(path.Join(job.dest, filepath.Base(filepath.Clean(p)))))
		}
		if out, err := runRemote(client, "ls -ld "+strings.Join(names, " "), ""); err == nil {
			d.Print(out)
		}
		return 0
	}
}

// demoTransfer is transferScript for the demo cluster: nothing is sent.
func demoTransfer(job transferJob) func(d *demoTerm) int {
	return func(d *demoTerm) int {
		name := "media"
		if len(job.paths) > 0 {
			name = filepath.Base(filepath.Clean(job.paths[0]))
		}
		d.Print("\n  " + strings.Join(job.paths, "\n  ") + "\n")
		d.Printf("\n128 file(s), 2.4 GiB  ->  %s@%s:%s\n\n", job.node.User, orDefault(job.node.Name, job.node.Host), job.dest)
		d.Print(cInfo + "Connecting to " + job.node.Host + "...\n")
		for i := 0; i <= 20; i++ {
			pct := float64(i) * 5
			d.raw(fmt.Sprintf("\r  %5.1f%%  %s of 2.4 GiB  112.0 MiB/s   ", pct, fmtBytes(int64(pct/100*2.4*(1<<30)))))
			if !d.Sleep(150 * time.Millisecond) {
				return d.exitCode()
			}
		}
		d.Print("\n\n" + cOK + "Copied 128 file(s), 2.4 GiB in 22s.\n\n")
		d.Printf("drwxr-xr-x 4 %s %s 4096 Oct 13 20:15 %s\n", job.node.User, job.node.User, path.Join(job.dest, name))
		return 0
	}
}

// ---------------------------------------------------------------------------
// The form
// ---------------------------------------------------------------------------

func (w *workstation) transferFiles() {
	p := w.current

	// Nodes: the cluster's nodes, else the control plane this cluster is
	// paired with.
	rows := w.nodeCache
	if len(rows) == 0 && w.activity != nil {
		rows = w.activity.last // the node lights' latest poll
	}
	var nodes []hostEntry
	var ready []string // "Ready" / "NotReady" / "" (unknown)
	for _, r := range rows {
		host := r.host
		if host == "" {
			host = r.name
		}
		nodes = append(nodes, hostEntry{Name: r.name, Host: host, User: p.User, Port: 22})
		ready = append(ready, r.status)
	}
	if len(nodes) == 0 {
		nodes = append(nodes, hostEntry{Name: p.Host, Host: p.Host, User: p.User, Port: p.port()})
		ready = append(ready, "")
	}
	labels := make([]string, len(nodes))
	for i, n := range nodes {
		light := "[gray]●[-]"
		switch ready[i] {
		case "Ready":
			light = "[green]●[-]"
		case "":
		default:
			light = "[red]●[-]"
		}
		labels[i] = light + " " + tview.Escape(n.Name)
		if n.Host != n.Name {
			labels[i] += "  (" + n.Host + ")"
		}
		if ready[i] != "" && ready[i] != "Ready" {
			labels[i] += "  [red]off[-]"
		}
	}

	// The SSH user for each node: the one saved in the SSH Console for it,
	// else, when the users are named after their nodes (the paired control
	// plane's user is its node name), the node's name, else the paired user.
	store := loadHostStore()
	namedAfterNode := false
	for _, n := range nodes {
		if n.Host == p.Host && n.Name == p.User {
			namedAfterNode = true
		}
	}
	userFor := func(n hostEntry) string {
		for _, e := range store.Hosts {
			if e.User != "" && (e.Host == n.Host || (e.Name != "" && e.Name == n.Name)) {
				return e.User
			}
		}
		if namedAfterNode {
			return n.Name
		}
		return p.User
	}

	homeOf := func(user string) string {
		if user == "root" {
			return "/root/"
		}
		return "/home/" + user + "/"
	}

	errText := tview.NewTextView().SetDynamicColors(true)
	form := tview.NewForm()
	form.AddInputField("File or folder", "", 52, nil, nil)
	form.AddDropDown("Node", labels, 0, nil)
	form.AddInputField("SSH user", userFor(nodes[0]), 24, nil, nil)
	form.AddInputField("Folder on the node", homeOf(userFor(nodes[0])), 52, nil, nil)
	form.GetFormItemByLabel("File or folder").(*tview.InputField).
		SetPlaceholder("Type a location or drop here…").
		SetPlaceholderTextColor(tcell.ColorGray)

	// Keep the default folder in step with the user until it's edited.
	destField := form.GetFormItemByLabel("Folder on the node").(*tview.InputField)
	form.GetFormItemByLabel("SSH user").(*tview.InputField).SetChangedFunc(func(user string) {
		cur := destField.GetText()
		if cur == "" || cur == "/root/" || (strings.HasPrefix(cur, "/home/") && strings.Count(cur, "/") == 3 && strings.HasSuffix(cur, "/")) {
			destField.SetText(homeOf(strings.TrimSpace(user)))
		}
	})
	// Picking a node fills in its SSH user (set after the fields exist:
	// the drop-down calls this for its first option too).
	userField := form.GetFormItemByLabel("SSH user").(*tview.InputField)
	form.GetFormItemByLabel("Node").(*tview.DropDown).SetSelectedFunc(func(_ string, i int) {
		if i >= 0 && i < len(nodes) {
			userField.SetText(userFor(nodes[i]))
		}
	})

	closeForm := func() {
		w.pages.RemovePage("transferform")
		w.showCluster()
	}
	form.AddButton("Transfer", func() {
		paths := splitDropped(form.GetFormItemByLabel("File or folder").(*tview.InputField).GetText())
		i, _ := form.GetFormItemByLabel("Node").(*tview.DropDown).GetCurrentOption()
		user := strings.TrimSpace(form.GetFormItemByLabel("SSH user").(*tview.InputField).GetText())
		dest := strings.TrimSpace(destField.GetText())
		switch {
		case len(paths) == 0:
			errText.SetText("  [red]Drop a file or folder into the first box (or paste its path).[-]")
			return
		case user == "":
			errText.SetText("  [red]Enter the SSH user.[-]")
			return
		case !strings.HasPrefix(dest, "/"):
			errText.SetText("  [red]The folder on the node must be a full path, like " + homeOf(user) + "[-]")
			return
		}
		if !p.demo {
			for _, pth := range paths {
				if _, err := os.Stat(pth); err != nil {
					errText.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
					return
				}
			}
		}
		node := nodes[max(i, 0)]
		node.User = user
		job := transferJob{paths: paths, node: node, dest: dest, keys: []string{p.keyPath()}}
		w.pages.RemovePage("transferform")
		launch := termLaunch{
			title:  fmt.Sprintf("TRANSFER  →  %s@%s:%s", user, node.Name, dest),
			target: fmt.Sprintf("%s@%s:%d", user, node.Host, node.portOr22()),
			okText: "COPIED",
			demo:   transferScript(job),
		}
		if p.demo {
			launch.title = "DEMO · " + launch.title
			launch.demo = demoTransfer(job)
		}
		termPage.Open(launch, w.showCluster)
	})
	form.AddButton("Cancel", closeForm)
	form.SetCancelFunc(closeForm)
	styleForm(form)
	form.SetBorder(false)

	hint := `Drag them from Explorer into the box, or paste a path (C:\Users\me\Videos)`
	if runtime.GOOS != "windows" {
		hint = "Drag them into the box, or type a path (~/Videos)"
	}
	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetDynamicColors(true).SetText(
			"\n  [yellow::b]Transfer files to a node[-::-]\n"+
				"  Copies files or folders from this computer to a node over SSH.\n"+
				"  A folder arrives as that folder inside the one you choose.\n"+
				"  [gray]"+tview.Escape(hint)+"[-]"), 6, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(errText, 1, 0, false)
	panel.SetBorder(true).SetTitle(" TRANSFER ").SetTitleAlign(tview.AlignLeft)
	w.pages.AddPage("transferform", centered(panel, 84, 22), true, true)
	w.footer.SetText(" [aqua::b]TAB[-::-] Next field    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Cancel")
	w.app.SetFocus(form)
}

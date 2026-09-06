package ids

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Line is what every source delivers: where it came from and the text.
type Line struct {
	Source  string // journal | syslog | file | orbis
	Host    string
	Program string
	Text    string
}

// runJournal follows journald for the authentication programs and hands
// each message to sink until ctx ends. It returns when journalctl is not
// available.
func runJournal(ctx context.Context, sink func(Line), log func(string, ...any)) bool {
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		return false
	}
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, bin, "-f", "-n", "0", "-o", "json", "--no-pager",
			"-t", "sshd", "-t", "sshd-session", "-t", "login", "-t", "vsftpd", "-t", "dovecot", "-t", "postfix/smtpd", "-t", "openvpn", "-t", "sudo")
		out, err := cmd.StdoutPipe()
		if err != nil {
			return false
		}
		if err := cmd.Start(); err != nil {
			log("ids: journalctl: %v", err)
			return false
		}
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var rec struct {
				Message    any    `json:"MESSAGE"`
				Identifier string `json:"SYSLOG_IDENTIFIER"`
				Host       string `json:"_HOSTNAME"`
			}
			if json.Unmarshal(sc.Bytes(), &rec) != nil {
				continue
			}
			msg, _ := rec.Message.(string)
			if msg == "" {
				continue
			}
			sink(Line{Source: "journal", Host: rec.Host, Program: rec.Identifier, Text: msg})
		}
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return true
		}
		// journald rotated or the process died; come back in a moment.
		time.Sleep(5 * time.Second)
	}
	return true
}

// tailFile follows a log file from its end, surviving rotation.
func tailFile(ctx context.Context, path string, sink func(Line)) {
	var f *os.File
	var offset int64
	open := func() bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		st, err := nf.Stat()
		if err != nil {
			nf.Close()
			return false
		}
		f = nf
		offset = st.Size()
		_, _ = f.Seek(offset, io.SeekStart)
		return true
	}
	if !open() {
		return
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	r := bufio.NewReader(f)
	host, _ := os.Hostname()
	for ctx.Err() == nil {
		line, err := r.ReadString('\n')
		if err == nil {
			offset += int64(len(line))
			sink(Line{Source: "file", Host: host, Text: strings.TrimRight(line, "\r\n")})
			continue
		}
		time.Sleep(time.Second)
		if st, err := os.Stat(path); err == nil && st.Size() < offset {
			f.Close()
			if !open() {
				return
			}
			r = bufio.NewReader(f)
		}
	}
}

// authLogPath returns the classic auth log if this system writes one.
func authLogPath() string {
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// syslogReceiver listens on UDP and TCP for forwarded logs.
type syslogReceiver struct {
	addr string
	sink func(Line)
	log  func(string, ...any)

	mu       sync.Mutex
	udp      net.PacketConn
	tcp      net.Listener
	received int64
	hosts    map[string]time.Time
	senders  map[string]time.Time
}

func newSyslogReceiver(addr string, sink func(Line), log func(string, ...any)) *syslogReceiver {
	return &syslogReceiver{addr: addr, sink: sink, log: log, hosts: map[string]time.Time{}, senders: map[string]time.Time{}}
}

func (r *syslogReceiver) start(ctx context.Context) error {
	udp, err := net.ListenPacket("udp", r.addr)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", r.addr)
	if err != nil {
		udp.Close()
		return err
	}
	r.mu.Lock()
	r.udp, r.tcp = udp, tcp
	r.mu.Unlock()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			r.handle(from, string(buf[:n]))
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				sc.Buffer(make([]byte, 64*1024), 1024*1024)
				for sc.Scan() {
					r.handle(c.RemoteAddr(), sc.Text())
				}
			}(c)
		}
	}()
	go func() {
		<-ctx.Done()
		r.stop()
	}()
	return nil
}

func (r *syslogReceiver) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.udp != nil {
		r.udp.Close()
		r.udp = nil
	}
	if r.tcp != nil {
		r.tcp.Close()
		r.tcp = nil
	}
}

func (r *syslogReceiver) handle(from net.Addr, raw string) {
	sender := from.String()
	if h, _, err := net.SplitHostPort(sender); err == nil {
		sender = h
	}
	// A datagram can carry several lines; a TCP scanner delivers one.
	for _, part := range strings.Split(raw, "\n") {
		part = strings.TrimRight(part, "\r\x00")
		if part == "" {
			continue
		}
		m := ParseSyslog(part)
		if m.Host == "" {
			m.Host = sender
		}
		r.mu.Lock()
		r.received++
		r.hosts[m.Host] = time.Now()
		r.senders[sender] = time.Now()
		r.mu.Unlock()
		r.sink(Line{Source: "syslog", Host: m.Host, Program: m.Program, Text: m.Message})
	}
}

func (r *syslogReceiver) status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	var hosts []string
	for h, t := range r.hosts {
		if t.After(cut) {
			hosts = append(hosts, h)
		}
	}
	return map[string]any{"listen": r.addr, "running": r.udp != nil, "received": r.received, "hosts": hosts}
}

// fileBase is a helper for status messages.
func fileBase(p string) string { return filepath.Base(p) }

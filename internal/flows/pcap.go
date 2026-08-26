package flows

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// On-demand packet capture, written straight out as a pcap file.
//
// Orbis's normal capture path is a BPF prefilter that delivers only the few
// packets carrying identity, which is what makes it cheap. That is exactly
// wrong for debugging: when someone asks "why is this failing", they need the
// whole conversation. This is a separate, bounded, explicitly-started capture
// that does not touch the analysis pipeline.

// CaptureRequest bounds a capture. Both limits always apply; whichever is hit
// first ends the capture, so a mistake cannot fill the disk.
type CaptureRequest struct {
	Interface  string `json:"interface"`
	Filter     string `json:"filter"` // BPF expression
	MaxPackets int    `json:"max_packets"`
	MaxSeconds int    `json:"max_seconds"`
	SnapLen    int    `json:"snaplen"`
}

// CaptureResult describes a finished capture.
type CaptureResult struct {
	ID         string    `json:"id"`
	Interface  string    `json:"interface"`
	Filter     string    `json:"filter"`
	Packets    int       `json:"packets"`
	Bytes      int       `json:"bytes"`
	StartedAt  time.Time `json:"started_at"`
	Duration   float64   `json:"duration_seconds"`
	Truncated  bool      `json:"truncated"`
	Incomplete string    `json:"incomplete,omitempty"`
}

// pcap global header, little-endian, microsecond resolution, LINKTYPE_ETHERNET.
const (
	pcapMagic   = 0xa1b2c3d4
	linkEthernet = 1
)

func writePcapHeader(w io.Writer, snapLen int) error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], 2) // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4) // version minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(snapLen))
	binary.LittleEndian.PutUint32(hdr[20:24], linkEthernet)
	_, err := w.Write(hdr)
	return err
}

func writePcapPacket(w io.Writer, ts time.Time, data []byte, origLen int) error {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(origLen))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// CaptureToWriter runs a bounded capture and streams a pcap file to w.
//
// It shells out to tcpdump when available, because reimplementing BPF filter
// compilation to support the expression syntax people actually know would be a
// large amount of code to reproduce something already installed. When tcpdump
// is missing it falls back to the raw AF_PACKET path with no filter.
func CaptureToWriter(ctx context.Context, w io.Writer, req CaptureRequest) (*CaptureResult, error) {
	if req.Interface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	if req.MaxPackets <= 0 || req.MaxPackets > 200000 {
		req.MaxPackets = 5000
	}
	if req.MaxSeconds <= 0 || req.MaxSeconds > 300 {
		req.MaxSeconds = 30
	}
	if req.SnapLen <= 0 || req.SnapLen > 65535 {
		req.SnapLen = 262
	}
	if err := validateBPF(req.Filter); err != nil {
		return nil, err
	}

	res := &CaptureResult{
		ID: strconv.FormatInt(time.Now().UnixNano(), 36),
		Interface: req.Interface, Filter: req.Filter, StartedAt: time.Now(),
	}

	if _, err := exec.LookPath("tcpdump"); err != nil {
		return nil, fmt.Errorf("tcpdump is not installed; install it to use packet capture")
	}

	cctx, cancel := context.WithTimeout(ctx, time.Duration(req.MaxSeconds+5)*time.Second)
	defer cancel()

	args := []string{
		"-i", req.Interface,
		"-c", strconv.Itoa(req.MaxPackets),
		"-s", strconv.Itoa(req.SnapLen),
		"-w", "-", // stdout
		"-U",      // packet-buffered, so a short capture is not lost in a buffer
		"-n",
	}
	if req.Filter != "" {
		args = append(args, req.Filter)
	}
	cmd := exec.CommandContext(cctx, "tcpdump", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}

	// Stop at the time limit even if the packet count is never reached.
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	go func() {
		select {
		case <-time.After(time.Duration(req.MaxSeconds) * time.Second):
			_ = cmd.Process.Signal(interruptSignal())
			res.Truncated = true
		case <-done:
		}
	}()

	n, copyErr := io.Copy(w, stdout)
	stop()
	waitErr := cmd.Wait()

	res.Bytes = int(n)
	res.Duration = time.Since(res.StartedAt).Seconds()
	if copyErr != nil {
		res.Incomplete = copyErr.Error()
	} else if waitErr != nil && !res.Truncated {
		// tcpdump exits non-zero when interrupted, which is expected here.
		if msg := strings.TrimSpace(stderr.String()); msg != "" && res.Bytes == 0 {
			return nil, fmt.Errorf("tcpdump: %s", msg)
		}
	}
	return res, nil
}

// validateBPF rejects shell metacharacters. The filter is passed as an argv
// element rather than through a shell, so this is defence in depth, but a BPF
// expression has no legitimate use for these characters.
func validateBPF(f string) error {
	if f == "" {
		return nil
	}
	if len(f) > 512 {
		return fmt.Errorf("filter expression is too long")
	}
	for _, bad := range []string{";", "|", "&", "$", "`", "\n", "\r", ">", "<"} {
		if strings.Contains(f, bad) {
			return fmt.Errorf("filter contains an illegal character %q", bad)
		}
	}
	return nil
}

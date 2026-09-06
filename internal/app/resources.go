package app

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resources is what the node is spending: the daemon's own CPU share and
// memory, and the host's CPU, memory, load and temperature. Sampled every
// five seconds so a page poll reads a number rather than causing work.
type Resources struct {
	SampledAt     time.Time `json:"sampled_at"`
	ProcessCPU    float64   `json:"process_cpu_percent"` // percent of one core
	HostCPU       float64   `json:"host_cpu_percent"`    // percent of all cores
	Cores         int       `json:"cores"`
	RSSBytes      uint64    `json:"rss_bytes"`
	HeapBytes     uint64    `json:"heap_bytes"`
	GoSysBytes    uint64    `json:"go_sys_bytes"`
	Goroutines    int       `json:"goroutines"`
	MemTotal      uint64    `json:"mem_total_bytes"`
	MemAvailable  uint64    `json:"mem_available_bytes"`
	Load1         float64   `json:"load1"`
	Load5         float64   `json:"load5"`
	Load15        float64   `json:"load15"`
	TempC         float64   `json:"temp_c,omitempty"`
	Throttled     string    `json:"throttled,omitempty"`
	UptimeSeconds int       `json:"uptime_seconds"`
}

type resourceSampler struct {
	mu        sync.Mutex
	last      Resources
	prevProc  float64 // process CPU seconds
	prevHost  [2]uint64
	prevAt    time.Time
	clockTick float64
}

func newResourceSampler() *resourceSampler {
	return &resourceSampler{clockTick: 100}
}

// Resources returns the last sample.
func (a *App) Resources() Resources {
	if a.res == nil {
		return Resources{}
	}
	a.res.mu.Lock()
	defer a.res.mu.Unlock()
	r := a.res.last
	r.UptimeSeconds = int(a.Uptime().Seconds())
	return r
}

func (a *App) sampleResources(ctx context.Context) {
	a.res.sample()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.res.sample()
		}
	}
}

func (s *resourceSampler) sample() {
	now := time.Now()
	var r Resources
	r.SampledAt = now
	r.Cores = runtime.NumCPU()
	r.Goroutines = runtime.NumGoroutine()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.HeapBytes, r.GoSysBytes = ms.HeapAlloc, ms.Sys

	// The daemon's own CPU: utime+stime from /proc/self/stat, in clock ticks.
	if proc, ok := readProcCPU(); ok {
		s.mu.Lock()
		if !s.prevAt.IsZero() {
			if dt := now.Sub(s.prevAt).Seconds(); dt > 0 {
				r.ProcessCPU = (proc - s.prevProc) / dt * 100
			}
		}
		s.prevProc = proc
		s.mu.Unlock()
	}
	// The host: /proc/stat's first line, busy against total.
	if busy, total, ok := readHostCPU(); ok {
		s.mu.Lock()
		if s.prevHost[1] > 0 && total > s.prevHost[1] {
			r.HostCPU = float64(busy-s.prevHost[0]) / float64(total-s.prevHost[1]) * 100
		}
		s.prevHost = [2]uint64{busy, total}
		s.mu.Unlock()
	}
	r.RSSBytes = readRSS()
	r.MemTotal, r.MemAvailable = readMemInfo()
	r.Load1, r.Load5, r.Load15 = readLoad()
	r.TempC = readTemp()
	r.Throttled = readThrottled()
	if r.ProcessCPU < 0 {
		r.ProcessCPU = 0
	}
	s.mu.Lock()
	s.prevAt = now
	s.last = r
	s.mu.Unlock()
}

func readProcCPU() (float64, bool) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, false
	}
	// Everything after the last ')' is space-separated; utime and stime are
	// fields 14 and 15 of the whole line, so 12 and 13 after the name.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 13 {
		return 0, false
	}
	ut, err1 := strconv.ParseFloat(f[11], 64)
	st, err2 := strconv.ParseFloat(f[12], 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return (ut + st) / 100, true
}

func readHostCPU() (busy, total uint64, ok bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	var vals []uint64
	for _, x := range f[1:] {
		v, err := strconv.ParseUint(x, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		vals = append(vals, v)
	}
	for _, v := range vals {
		total += v
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4] // iowait counts as idle
	}
	return total - idle, total, true
}

func readRSS() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, _ := strconv.ParseUint(f[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func readMemInfo() (total, available uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			available = kb * 1024
		}
	}
	return total, available
}

func readLoad() (l1, l5, l15 float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, 0
	}
	l1, _ = strconv.ParseFloat(f[0], 64)
	l5, _ = strconv.ParseFloat(f[1], 64)
	l15, _ = strconv.ParseFloat(f[2], 64)
	return l1, l5, l15
}

func readTemp() float64 {
	for _, p := range []string{"/sys/class/thermal/thermal_zone0/temp", "/sys/class/hwmon/hwmon0/temp1_input", "/sys/class/hwmon/hwmon1/temp1_input"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		if err != nil || v <= 0 {
			continue
		}
		if v > 1000 {
			v /= 1000
		}
		return v
	}
	return 0
}

// readThrottled decodes the Raspberry Pi firmware's throttle word: the low
// bits are "now", the high bits "since boot".
func readThrottled() string {
	b, err := os.ReadFile("/sys/devices/platform/soc/soc:firmware/get_throttled")
	if err != nil {
		return ""
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 32)
	if err != nil {
		return ""
	}
	var now, past []string
	if v&0x1 != 0 {
		now = append(now, "under-voltage")
	}
	if v&0x2 != 0 {
		now = append(now, "frequency capped")
	}
	if v&0x4 != 0 {
		now = append(now, "throttled")
	}
	if v&0x8 != 0 {
		now = append(now, "at the temperature limit")
	}
	if v&0x10000 != 0 {
		past = append(past, "under-voltage")
	}
	if v&0x20000 != 0 {
		past = append(past, "frequency capped")
	}
	if v&0x40000 != 0 {
		past = append(past, "throttled")
	}
	if v&0x80000 != 0 {
		past = append(past, "at the temperature limit")
	}
	switch {
	case len(now) > 0:
		return "now: " + strings.Join(now, ", ")
	case len(past) > 0:
		return "since boot: " + strings.Join(past, ", ") + " (check the power supply)"
	default:
		return "ok"
	}
}

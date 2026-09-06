// Command orbisd is the Orbis daemon: an AI-assisted network firewall,
// ad-blocking resolver, traffic analyser and VPN gateway in one process.
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Neoo-Blue/orbis/internal/api"
	"github.com/Neoo-Blue/orbis/internal/app"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/mcp"
	"github.com/Neoo-Blue/orbis/internal/update"
)

// version is overwritten at build time with -ldflags "-X main.version=...".
var version = "dev"

// The built UI is embedded so the daemon is a single deployable file. The
// directive tolerates an absent build (the placeholder page is served then).
//
//go:embed all:web
var webAssets embed.FS

func main() {
	var (
		configPath  = flag.String("config", "/etc/orbis/orbis.yaml", "path to the configuration file")
		showVersion = flag.Bool("version", false, "print version and exit")
		checkOnly   = flag.Bool("check", false, "validate the configuration and exit")
		printRules  = flag.Bool("print-ruleset", false, "render the nftables ruleset to stdout and exit")
		selfUpdate  = flag.Bool("update", false, "install the latest release from GitHub over this binary and exit")
		mcpMode     = flag.Bool("mcp", false, "run as a Model Context Protocol server on stdin/stdout")
		mcpWrite    = flag.Bool("mcp-write", false, "allow the MCP server to change configuration (off by default)")
		verbose     = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	// A small board has no memory cgroup to lean on, so the runtime itself
	// is told where the ceiling is: the collector works harder as the heap
	// nears it instead of the kernel killing the daemon at the wall.
	applyMemoryLimit()
	if *selfUpdate {
		os.Exit(runSelfUpdate())
	}
	// Profiling is opt-in and loopback-only: ORBIS_PPROF=127.0.0.1:6060.
	if addr := os.Getenv("ORBIS_PPROF"); addr != "" {
		startPprof(addr)
	}

	if *showVersion {
		fmt.Printf("orbisd %s\n", versionString())
		return
	}

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)
	logf := func(format string, args ...any) {
		logger.Printf(format, args...)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatalf("configuration: %v", err)
	}
	if *checkOnly {
		fmt.Printf("configuration at %s is valid (mode: %s)\n", *configPath, cfg.Mode)
		return
	}
	if *verbose {
		logf("orbis %s starting with config %s", versionString(), *configPath)
	}

	// Refusing to run as a non-root user would be wrong — the API and the UI
	// work fine unprivileged — but the operator should know what will not work.
	if os.Geteuid() != 0 {
		logf("warning: not running as root. Packet capture, nftables, DHCP and " +
			"WireGuard will be unavailable; the UI and API will still work.")
	}

	// Anything Load had to correct is worth saying loudly: it means the node
	// was not doing what its own configuration claimed.
	for _, note := range cfg.Notes {
		logf("config: %s", note)
	}

	application, err := app.New(cfg, logf)
	if err != nil {
		logger.Fatalf("startup: %v", err)
	}

	application.SetBuild(versionString())

	// MCP runs instead of the daemon, not alongside it: it speaks JSON-RPC on
	// stdout, so anything else logging there would corrupt the stream. Logs go
	// to stderr for the same reason.
	if *mcpMode {
		mcp.Version = versionString()
		srv := mcp.New(application, *mcpWrite, logf)
		if err := srv.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			logger.Fatalf("mcp: %v", err)
		}
		return
	}

	if *printRules {
		ruleset, err := application.Firewall.Render()
		if err != nil {
			logger.Fatalf("render ruleset: %v", err)
		}
		fmt.Print(ruleset)
		return
	}

	application.Start()

	var uiFS fs.FS = webAssets
	if sub, err := fs.Sub(webAssets, "web"); err == nil {
		uiFS = sub
	}
	server := api.New(application, cfg, uiFS, logf)
	if err := server.Start(); err != nil {
		application.Stop()
		logger.Fatalf("api: %v", err)
	}

	logf("orbis %s ready, open http://%s", versionString(), cfg.API.Listen)
	if cfg.Mode == config.ModeObserve {
		logf("running in OBSERVE mode: nothing is routed through this node and no " +
			"ruleset is installed. Switch to inline mode when you are ready to enforce.")
	}

	// Wait for a signal, then shut down in the right order: stop accepting
	// new work, then drain, then close the database.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logf("received %s, shutting down", sig)

	done := make(chan struct{})
	go func() {
		_ = server.Stop()
		application.Stop()
		close(done)
	}()
	select {
	case <-done:
		logf("shutdown complete")
	case <-time.After(20 * time.Second):
		// A subsystem wedged on a syscall should not hold the box hostage;
		// the store commits on every batch, so the loss is bounded.
		logf("shutdown timed out after 20s, exiting anyway")
	}
}

// versionString prefers the linker-injected version and falls back to the
// VCS revision Go stamps into the binary, so an unversioned build still says
// something useful.
func versionString() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 7 {
				rev = s.Value[:7]
			} else {
				rev = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev != "" {
		return "dev+" + rev + dirty
	}
	return version
}

// applyMemoryLimit sets the Go soft memory limit to 70% of physical memory
// unless GOMEMLIMIT already says otherwise.
func applyMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb <= 0 {
			return
		}
		limit := kb * 1024 * 7 / 10
		if limit < 512<<20 {
			limit = 512 << 20
		}
		debug.SetMemoryLimit(limit)
		log.Printf("memory limit %d MB (70%% of %d MB)", limit>>20, kb>>10)
		return
	}
}

// startPprof serves net/http/pprof on a loopback address for diagnosis.
func startPprof(addr string) {
	if !strings.HasPrefix(addr, "127.") && !strings.HasPrefix(addr, "localhost") && !strings.HasPrefix(addr, "[::1]") {
		log.Printf("pprof: refusing to listen on %s; loopback only", addr)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	go func() {
		log.Printf("pprof: listening on %s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("pprof: %v", err)
		}
	}()
}

// runSelfUpdate is the headless path: check, install, restart, report.
func runSelfUpdate() int {
	m := update.NewManager(versionString(), "", update.Hooks{}, log.Printf)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	rel, err := m.Check(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		return 1
	}
	if !update.Newer(rel.Version, versionString()) {
		fmt.Printf("already up to date: %s (latest release %s)\n", versionString(), rel.Version)
		return 0
	}
	fmt.Printf("updating %s -> %s\n", versionString(), rel.Version)
	if err := m.Apply(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "update:", err)
		return 1
	}
	last := ""
	for {
		st := m.Status()
		state, _ := st["state"].(string)
		if state != last {
			fmt.Println(state)
			last = state
		}
		switch state {
		case "error":
			fmt.Fprintln(os.Stderr, st["error"])
			return 1
		case "restarting", "installed":
			fmt.Println("done")
			return 0
		}
		time.Sleep(500 * time.Millisecond)
	}
}

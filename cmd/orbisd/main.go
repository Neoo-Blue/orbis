// Command orbisd is the Orbis daemon: an AI-assisted network firewall,
// ad-blocking resolver, traffic analyser and VPN gateway in one process.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Neoo-Blue/orbis/internal/api"
	"github.com/Neoo-Blue/orbis/internal/app"
	"github.com/Neoo-Blue/orbis/internal/config"
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
		verbose     = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

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

	application, err := app.New(cfg, logf)
	if err != nil {
		logger.Fatalf("startup: %v", err)
	}

	application.SetBuild(versionString())

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

	logf("orbis %s ready — open http://%s", versionString(), cfg.API.Listen)
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

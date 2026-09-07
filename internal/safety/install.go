package safety

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Install writes the units and the watchdog drop-in and reloads systemd.
// It must run as root outside the service sandbox: the installer does, and
// the daemon delegates to a transient unit for the same reason it does when
// updating itself.
func Install(ctx context.Context, o UnitOptions, hardwareWatchdog bool, log func(string, ...any)) ([]string, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	var changed []string
	write := func(path, content string) error {
		if old, err := os.ReadFile(path); err == nil && string(old) == content {
			return nil
		}
		if err := writeAtomic(path, content); err != nil {
			return err
		}
		changed = append(changed, path)
		return nil
	}
	if err := write(UnitPath, MainUnit(o)); err != nil {
		return changed, fmt.Errorf("%s: %w", UnitPath, err)
	}
	if o.Lifeboat {
		if err := write(LifeboatUnitPath, LifeboatUnit(o)); err != nil {
			return changed, fmt.Errorf("%s: %w", LifeboatUnitPath, err)
		}
	}
	// The hardware watchdog only where there is one, and only from the next
	// boot: the setting is written for systemd to read at startup and is
	// never applied live. Re-executing systemd to arm a watchdog reset a
	// Raspberry Pi mid-write once, which is the opposite of a safety net.
	if hardwareWatchdog && HasHardwareWatchdog() {
		if err := write(WatchdogConfPath, WatchdogConf()); err != nil {
			return changed, fmt.Errorf("%s: %w", WatchdogConfPath, err)
		}
	} else if _, err := os.Stat(WatchdogConfPath); err == nil {
		if err := os.Remove(WatchdogConfPath); err == nil {
			changed = append(changed, WatchdogConfPath+" (removed)")
		}
	}
	if len(changed) == 0 {
		return nil, nil
	}
	if d, err := os.Open(filepath.Dir(UnitPath)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return changed, fmt.Errorf("daemon-reload: %s", strings.TrimSpace(string(out)))
	}
	log("safety: installed %s", strings.Join(changed, ", "))
	return changed, nil
}

// writeAtomic writes through a temporary file, flushes it to disk, and
// renames it into place, so a reset at any moment leaves either the old
// file or the new one, never an empty one.
func writeAtomic(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// HasHardwareWatchdog reports whether the kernel exposes a watchdog device.
func HasHardwareWatchdog() bool {
	_, err := os.Stat("/dev/watchdog")
	return err == nil
}

// Retry asks systemd to start the main service again, from the lifeboat.
func Retry(ctx context.Context) error {
	_ = exec.CommandContext(ctx, "systemctl", "reset-failed", "orbis.service").Run()
	out, err := exec.CommandContext(ctx, "systemctl", "start", "--no-block", "orbis.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ServiceStatus is `systemctl status` for the page, trimmed.
func ServiceStatus(ctx context.Context, unit string, lines int) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, "systemctl", "status", unit, "--no-pager", "-n", fmt.Sprint(lines)).CombinedOutput()
	return string(bytes.TrimSpace(out))
}

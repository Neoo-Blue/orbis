// Package sdnotify speaks systemd's notification protocol: READY when the
// service is serving, WATCHDOG heartbeats while it is healthy, STATUS lines
// for `systemctl status`. Outside systemd every call is a no-op.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends one state line. It never blocks and never fails loudly.
func Notify(state string) bool {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return false
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return false
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err == nil
}

func Ready() bool            { return Notify("READY=1") }
func Watchdog() bool         { return Notify("WATCHDOG=1") }
func Status(msg string) bool { return Notify("STATUS=" + msg) }
func Stopping() bool         { return Notify("STOPPING=1") }
func Enabled() bool          { return os.Getenv("NOTIFY_SOCKET") != "" }

// WatchdogInterval is the period systemd expects a heartbeat within, when
// WatchdogSec= is set on the unit and this process is the one it watches.
func WatchdogInterval() (time.Duration, bool) {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0, false
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0, false
	}
	return time.Duration(usec) * time.Microsecond, true
}

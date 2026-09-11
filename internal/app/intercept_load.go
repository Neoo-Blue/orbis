package app

import (
	"fmt"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// Every intercepted device's connections become flow rows, so interception
// multiplies what the node writes. On a Raspberry Pi with an SD card, enrolling
// storage and servers took the flow rate from ~100 to ~650 a minute and kept
// the card busy until the whole daemon stalled (Sep 2026). loadGuard notices a
// node that is not keeping up and turns interception off, so the fix for a
// slow network is never "wait for someone to notice Orbis".
type loadGuard struct {
	prev     store.WriteStats
	prevAt   time.Time
	strained int // consecutive strained minutes while intercepting
}

const (
	// strainDuty is the share of wall time the log writer may spend on the
	// disk before it counts as saturated. A healthy node sits in single digits.
	strainDuty = 0.6
	// strainMinutes of strain in a row turn interception off. A blocklist
	// refresh can keep the disk busy for a few minutes on its own.
	strainMinutes = 5
)

// guardInterceptLoad samples the store's writer once a minute.
func (a *App) guardInterceptLoad(now time.Time) {
	g := &a.interceptLoad
	ws := a.Store.WriteStats()
	prev, prevAt := g.prev, g.prevAt
	g.prev, g.prevAt = ws, now
	if prevAt.IsZero() || !now.After(prevAt) {
		return
	}
	duty := float64(ws.BusyNanos-prev.BusyNanos) / float64(now.Sub(prevAt).Nanoseconds())
	dropped := ws.Dropped - prev.Dropped

	if a.Intercept == nil || !a.Intercept.Running() {
		g.strained = 0
		return
	}
	if duty < strainDuty && dropped == 0 {
		if g.strained > 0 {
			a.log("intercept: node caught up (log writer %.0f%% busy)", duty*100)
		}
		g.strained = 0
		return
	}
	g.strained++
	a.log("intercept: node is straining: log writer %.0f%% busy, %d row(s) dropped in the last minute (%d of %d)",
		duty*100, dropped, g.strained, strainMinutes)
	if g.strained < strainMinutes {
		return
	}
	g.strained = 0
	a.pauseInterceptForLoad(duty, dropped)
}

// pauseInterceptForLoad turns interception off and says why. It is saved, so a
// restart does not put the node straight back under the same load.
func (a *App) pauseInterceptForLoad(duty float64, dropped uint64) {
	n := len(a.Cfg.Snapshot().Network.Intercept.Clients)
	if err := a.Cfg.Update(func(c *config.Config) { c.Network.Intercept.Enabled = false }); err != nil {
		a.log("intercept: could not save interception as off: %v", err)
	}
	if err := a.SyncIntercept(); err != nil {
		a.log("intercept: %v", err)
	}
	a.log("intercept: turned off, the node could not keep up with %d intercepted device(s)", n)
	a.raise(store.SevCritical, "intercept", "Interception turned off: this node could not keep up",
		fmt.Sprintf("For %d minutes in a row the log writer was %.0f%% busy (%d row(s) dropped in the last minute) "+
			"while carrying the traffic of %d device(s). Every device was sent back to the router directly so the "+
			"network stays fast. Storage and servers move a lot of data: enrol fewer devices, ideally only phones "+
			"and laptops, before turning interception back on.", strainMinutes, duty*100, dropped, n))
}

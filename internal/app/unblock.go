package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/blockpage"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/unblock"
	"golang.org/x/net/publicsuffix"
)

// ErrTooBroad refuses opening a site on a threat list for everyone for good.
// One device for a while is a decision; the whole network forever belongs in
// the owner's own rules, with the list in front of them.
var ErrTooBroad = errors.New("a site on a threat list can only be allowed for this device, for a limited time")

// ErrNotBlocked refuses a request for a name that is not stopped for this
// device. A grant opens everything under a name, so asking must not reach
// further than what the block page was showing.
var ErrNotBlocked = errors.New("this site is not blocked for this device")

// HowLong puts a request's length into words.
func HowLong(minutes int) string {
	switch minutes {
	case 0:
		return "always"
	case 15:
		return "for 15 minutes"
	case 1440:
		return "for today"
	}
	return "for 1 hour"
}

// adminBase is this node's interface, as this client reaches it.
func (a *App) adminBase(client netip.Addr) string {
	addr, ok := a.BlockGuard.Reach(client, time.Now())
	if !ok {
		return ""
	}
	port := ""
	if _, p, err := net.SplitHostPort(a.Cfg.Snapshot().API.Listen); err == nil && p != "80" {
		port = ":" + p
	}
	return fmt.Sprintf("http://%s%s", addr, port)
}

func (a *App) unblockRequest(host string, form blockpage.AskForm, client netip.Addr) (unblock.Request, error) {
	page := a.explainBlock(context.Background(), host, client)
	if suffix, _ := publicsuffix.PublicSuffix(strings.ToLower(host)); !page.Blocked || suffix == strings.ToLower(host) {
		return unblock.Request{}, ErrNotBlocked
	}
	clientID, _ := a.clientForAddr(client)
	return unblock.Request{
		Host: host, ClientID: clientID, ClientIP: client.String(), Device: oneLine(firstNonEmpty(page.Device, client.String())),
		Note: oneLine(form.Note), Reason: form.Reason, Wants: form.Minutes,
		Why: page.Why, Category: page.Category, Risky: page.Risky,
	}, nil
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func askState(r *unblock.Request) blockpage.AskState {
	if r == nil {
		return blockpage.AskState{}
	}
	return blockpage.AskState{State: string(r.State)}
}

// AskUnblock records a request from the block page and tells the owner.
func (a *App) AskUnblock(host string, form blockpage.AskForm, client netip.Addr) (blockpage.AskState, error) {
	req, err := a.unblockRequest(host, form, client)
	if err != nil {
		return blockpage.AskState{}, err
	}
	r, isNew, err := a.Unblock.Ask(req, time.Now())
	if err != nil {
		return blockpage.AskState{}, err
	}
	if isNew {
		detail := fmt.Sprintf("Wants it %s.\n%s", HowLong(r.Wants), r.Why)
		if r.Reason != "" {
			detail = fmt.Sprintf("For %s, wants it %s.\n%s", r.Reason, HowLong(r.Wants), r.Why)
		}
		if r.Note != "" {
			detail = fmt.Sprintf("They say: %s\n%s", r.Note, detail)
		}
		data := map[string]any{}
		if base := a.adminBase(client); base != "" {
			link := fmt.Sprintf("%s/unblock/%s", base, r.ID)
			detail += fmt.Sprintf("\nAnswer in one tap: %s?t=%s", link, a.Unblock.Token(r.ID))
			data["approve_url"], data["token"], data["wants"] = link, a.Unblock.Token(r.ID), r.Wants
		}
		a.emit(store.Event{Severity: store.SevWarning, Category: "unblock", ClientID: r.ClientID,
			Title: fmt.Sprintf("%s asks to open %s", r.Device, r.Host), Detail: detail, Data: data})
		a.Bus.Publish(Event{Type: "unblock.pending", Data: r})
	}
	return askState(r), nil
}

// AskStatus tells the block page where its request stands.
func (a *App) AskStatus(host string, client netip.Addr) blockpage.AskState {
	clientID, _ := a.clientForAddr(client)
	return askState(a.Unblock.Status(clientID, host, time.Now()))
}

// trustedNow asks about the hardware behind an address, not the record that
// address last belonged to: a guest could take it over from a trusted device.
// One who copies the MAC as well still passes, the limit of trusting a device
// on a LAN at all.
func (a *App) trustedNow(client netip.Addr) bool {
	clientID, _ := a.clientForAddr(client)
	if clientID == "" || !a.Unblock.Trusted(clientID) {
		return false
	}
	c := a.Registry.ByIP(client)
	return c != nil && c.MAC != "" && strings.EqualFold(c.MAC, neighbourMAC(client))
}

func neighbourMAC(addr netip.Addr) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "neigh", "show", addr.String()).Output()
	if err != nil {
		return ""
	}
	return lladdr(string(out))
}

func lladdr(neigh string) string {
	if _, rest, ok := strings.Cut(neigh, "lladdr "); ok {
		if f := strings.Fields(rest); len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

// SelfUnblock opens a name for a trusted device without asking anyone.
func (a *App) SelfUnblock(host string, minutes int, client netip.Addr) (blockpage.AskState, error) {
	if !a.trustedNow(client) {
		return blockpage.AskState{}, errors.New("this device is not trusted to unblock")
	}
	req, err := a.unblockRequest(host, blockpage.AskForm{Minutes: minutes}, client)
	if err != nil {
		return blockpage.AskState{}, err
	}
	r, err := a.Unblock.Grant(req, time.Duration(minutes)*time.Minute, time.Now())
	if err != nil {
		return blockpage.AskState{}, err
	}
	a.Store.Audit(r.Device, "unblock.self", r.Host, "", r.Until.Format(time.RFC3339), "ok")
	// The owner hears about a threat-listed site, and the rest stay in the log.
	severity := store.SevInfo
	if r.Risky {
		severity = store.SevWarning
	}
	a.emit(store.Event{Severity: severity, Category: "unblock", ClientID: r.ClientID,
		Title: fmt.Sprintf("%s opened %s", r.Device, r.Host), Detail: "A trusted device did this itself, " + HowLong(minutes) + "."})
	a.Bus.Publish(Event{Type: "unblock.decided", Data: r})
	return askState(r), nil
}

// DecideUnblock answers a request.
func (a *App) DecideUnblock(id string, allow bool, minutes int, everyone bool, by string) (*unblock.Request, error) {
	if r, ok := a.Unblock.Get(id); ok && allow && r.Risky && (everyone || minutes <= 0) {
		return nil, ErrTooBroad
	}
	r, err := a.Unblock.Decide(id, allow, time.Duration(minutes)*time.Minute, everyone, by, time.Now())
	if err != nil {
		return nil, err
	}
	a.Store.Audit(by, "unblock.decide", r.Host, string(r.Device), string(r.State), "ok")
	a.Bus.Publish(Event{Type: "unblock.decided", Data: r})
	return r, nil
}

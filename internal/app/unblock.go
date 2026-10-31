package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/blockpage"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/unblock"
)

// ErrTooBroad refuses opening a site on a threat list for everyone for good.
// One device for a while is a decision; the whole network forever belongs in
// the owner's own rules, with the list in front of them.
var ErrTooBroad = errors.New("a site on a threat list can only be allowed for this device, for a limited time")

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
func (a *App) adminBase(client netip.Addr, host string) string {
	addr, ok := a.BlockGuard.AddrFor(client, host, time.Now())
	if !ok {
		return ""
	}
	port := ""
	if _, p, err := net.SplitHostPort(a.Cfg.Snapshot().API.Listen); err == nil && p != "80" {
		port = ":" + p
	}
	return fmt.Sprintf("http://%s%s", addr, port)
}

func (a *App) unblockRequest(host string, form blockpage.AskForm, client netip.Addr) unblock.Request {
	page := a.explainBlock(context.Background(), host, client)
	clientID, _ := a.clientForAddr(client)
	return unblock.Request{
		Host: host, ClientID: clientID, ClientIP: client.String(), Device: firstNonEmpty(page.Device, client.String()),
		Note: strings.Join(strings.Fields(form.Note), " "), Reason: form.Reason, Wants: form.Minutes,
		Why: page.Why, Category: page.Category, Risky: page.Risky,
	}
}

func askState(r *unblock.Request) blockpage.AskState {
	if r == nil {
		return blockpage.AskState{}
	}
	return blockpage.AskState{State: string(r.State)}
}

// AskUnblock records a request from the block page and tells the owner.
func (a *App) AskUnblock(host string, form blockpage.AskForm, client netip.Addr) (blockpage.AskState, error) {
	r, isNew, err := a.Unblock.Ask(a.unblockRequest(host, form, client), time.Now())
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
		if base := a.adminBase(client, host); base != "" {
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

// SelfUnblock opens a name for a trusted device without asking anyone.
func (a *App) SelfUnblock(host string, minutes int, client netip.Addr) (blockpage.AskState, error) {
	clientID, _ := a.clientForAddr(client)
	if clientID == "" || !a.Unblock.Trusted(clientID) {
		return blockpage.AskState{}, errors.New("this device is not trusted to unblock")
	}
	r, err := a.Unblock.Grant(a.unblockRequest(host, blockpage.AskForm{Minutes: minutes}, client), time.Duration(minutes)*time.Minute, time.Now())
	if err != nil {
		return blockpage.AskState{}, err
	}
	a.Store.Audit(r.Device, "unblock.self", r.Host, "", r.Until.Format(time.RFC3339), "ok")
	a.Bus.Publish(Event{Type: "unblock.decided", Data: r})
	return askState(r), nil
}

// DecideUnblock answers a request.
func (a *App) DecideUnblock(id string, allow bool, minutes int, everyone bool, by string) (*unblock.Request, error) {
	if r, ok := a.Unblock.Get(id); ok && allow && r.Risky && (everyone || minutes == 0) {
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

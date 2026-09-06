// Package upnp is a small UPnP Internet Gateway Device client: enough to find
// the router, read its external address, list its port mappings, and add or
// remove one. It exists so a node that is not the gateway can still offer
// "forward this port" and have it mean something.
package upnp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Gateway is a discovered IGD with the control endpoint of its WAN
// connection service.
type Gateway struct {
	Location     string `json:"location"`
	ControlURL   string `json:"control_url"`
	ServiceType  string `json:"service_type"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	// LocalAddr is the address this node used to reach the gateway; it is
	// what a mapping's InternalClient defaults to.
	LocalAddr string `json:"local_addr,omitempty"`
}

// Mapping is one row of the router's port mapping table.
type Mapping struct {
	ExtPort     int    `json:"ext_port"`
	Proto       string `json:"proto"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Lease       int    `json:"lease_seconds"`
	RemoteHost  string `json:"remote_host,omitempty"`
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

var serviceTypes = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// Discover finds an IGD with SSDP and reads its description. It returns the
// first gateway that offers a WAN connection service.
func Discover(ctx context.Context) (*Gateway, error) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2"} {
		msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
		if _, err := conn.WriteTo([]byte(msg), dst); err != nil {
			return nil, err
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 4096)
	seen := map[string]bool{}
	var lastErr error
	var server string
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		resp := string(buf[:n])
		loc := headerValue(resp, "location")
		if loc == "" || seen[loc] {
			continue
		}
		seen[loc] = true
		server = headerValue(resp, "server")
		gw, err := describe(ctx, loc)
		if err != nil {
			lastErr = err
			continue
		}
		return gw, nil
	}
	if lastErr != nil {
		who := "the router"
		if server != "" {
			who = "the router (" + server + ")"
		}
		if strings.Contains(strings.ToLower(server), "eero") {
			return nil, fmt.Errorf("%s announces UPnP but never serves its description, so it cannot be controlled this way; eero port forwards are set in the eero app", who)
		}
		return nil, fmt.Errorf("%s announced UPnP but its description could not be read: %w", who, lastErr)
	}
	return nil, errors.New("no UPnP gateway answered; UPnP may be switched off on the router")
}

func headerValue(resp, name string) string {
	for _, line := range strings.Split(resp, "\r\n") {
		if i := strings.IndexByte(line, ':'); i > 0 && strings.EqualFold(strings.TrimSpace(line[:i]), name) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

// description is the subset of the device description document we read.
type description struct {
	Device device `xml:"device"`
}

type device struct {
	FriendlyName string    `xml:"friendlyName"`
	Manufacturer string    `xml:"manufacturer"`
	ModelName    string    `xml:"modelName"`
	Services     []service `xml:"serviceList>service"`
	Devices      []device  `xml:"deviceList>device"`
}

type service struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

func describe(ctx context.Context, location string) (*Gateway, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc description
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse description: %w", err)
	}
	svc := findService(doc.Device)
	if svc == nil {
		return nil, errors.New("no WAN connection service in the description")
	}
	base, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	ctl, err := base.Parse(svc.ControlURL)
	if err != nil {
		return nil, err
	}
	gw := &Gateway{
		Location: location, ControlURL: ctl.String(), ServiceType: svc.ServiceType,
		Manufacturer: doc.Device.Manufacturer, Model: doc.Device.ModelName, FriendlyName: doc.Device.FriendlyName,
	}
	if la := localAddrFor(base.Host); la != "" {
		gw.LocalAddr = la
	}
	return gw, nil
}

func findService(d device) *service {
	for _, want := range serviceTypes {
		if s := findServiceType(d, want); s != nil {
			return s
		}
	}
	return nil
}

func findServiceType(d device, want string) *service {
	for i := range d.Services {
		if d.Services[i].ServiceType == want {
			return &d.Services[i]
		}
	}
	for _, sub := range d.Devices {
		if s := findServiceType(sub, want); s != nil {
			return s
		}
	}
	return nil
}

// localAddrFor finds which of our addresses routes to the gateway.
func localAddrFor(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort(host, "1900"), time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// soap sends one action and returns the response body.
func (g *Gateway) soap(ctx context.Context, action string, args [][2]string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:`)
	b.WriteString(action)
	b.WriteString(` xmlns:u="` + g.ServiceType + `">`)
	for _, kv := range args {
		b.WriteString("<" + kv[0] + ">")
		xml.EscapeText(&b, []byte(kv[1]))
		b.WriteString("</" + kv[0] + ">")
	}
	b.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.ControlURL, bytes.NewReader(b.Bytes()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.ServiceType+"#"+action+`"`)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		code, desc := soapError(body)
		if code != "" {
			return body, &Error{Code: code, Description: desc, Action: action}
		}
		return body, fmt.Errorf("%s: http %d", action, resp.StatusCode)
	}
	return body, nil
}

// Error is a UPnP error the router returned, with its code (713 means "no
// such entry", 718 "conflict with another mapping", 725 "only permanent
// leases supported", 606 "action not authorized").
type Error struct {
	Code        string
	Description string
	Action      string
}

func (e *Error) Error() string {
	switch e.Code {
	case "718":
		return "the router already has a different mapping on that port"
	case "725":
		return "the router only accepts permanent mappings"
	case "606":
		return "the router refused: not authorized (many routers only map ports to the device asking)"
	case "729":
		return "the router refused: mapping to another device is not allowed"
	}
	if e.Description != "" {
		return fmt.Sprintf("router error %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("router error %s on %s", e.Code, e.Action)
}

func soapError(body []byte) (code, desc string) {
	return textOf(body, "errorCode"), textOf(body, "errorDescription")
}

// textOf returns the text of the first element with the given local name.
func textOf(body []byte, name string) string {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == name {
			var v string
			if err := dec.DecodeElement(&v, &se); err == nil {
				return strings.TrimSpace(v)
			}
			return ""
		}
	}
}

// ExternalIP asks the router for its public address.
func (g *Gateway) ExternalIP(ctx context.Context) (string, error) {
	body, err := g.soap(ctx, "GetExternalIPAddress", nil)
	if err != nil {
		return "", err
	}
	return textOf(body, "NewExternalIPAddress"), nil
}

// AddMapping forwards extPort on the router to host:port. Lease 0 asks for a
// permanent mapping; routers that refuse that get a week, which the caller
// renews.
func (g *Gateway) AddMapping(ctx context.Context, m Mapping) error {
	proto := strings.ToUpper(m.Proto)
	if proto != "TCP" && proto != "UDP" {
		return fmt.Errorf("protocol must be tcp or udp")
	}
	desc := m.Description
	if desc == "" {
		desc = "orbis"
	}
	_, err := g.soap(ctx, "AddPortMapping", [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(m.ExtPort)},
		{"NewProtocol", proto},
		{"NewInternalPort", strconv.Itoa(m.Port)},
		{"NewInternalClient", m.Host},
		{"NewEnabled", "1"},
		{"NewPortMappingDescription", desc},
		{"NewLeaseDuration", strconv.Itoa(m.Lease)},
	})
	return err
}

// DeleteMapping removes a forward by external port and protocol.
func (g *Gateway) DeleteMapping(ctx context.Context, extPort int, proto string) error {
	_, err := g.soap(ctx, "DeletePortMapping", [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(extPort)},
		{"NewProtocol", strings.ToUpper(proto)},
	})
	var ue *Error
	if errors.As(err, &ue) && (ue.Code == "714" || ue.Code == "713") {
		return nil // already gone
	}
	return err
}

// Mappings walks the router's table. Routers end the table with error 713
// (SpecifiedArrayIndexInvalid); anything else is reported.
func (g *Gateway) Mappings(ctx context.Context) ([]Mapping, error) {
	var out []Mapping
	for i := 0; i < 512; i++ {
		body, err := g.soap(ctx, "GetGenericPortMappingEntry", [][2]string{{"NewPortMappingIndex", strconv.Itoa(i)}})
		if err != nil {
			var ue *Error
			if errors.As(err, &ue) && (ue.Code == "713" || ue.Code == "714") {
				break
			}
			if len(out) > 0 {
				break
			}
			return nil, err
		}
		m := parseMapping(body)
		if m.ExtPort == 0 && m.Host == "" {
			break
		}
		out = append(out, m)
	}
	return out, nil
}

func parseMapping(body []byte) Mapping {
	ext, _ := strconv.Atoi(textOf(body, "NewExternalPort"))
	port, _ := strconv.Atoi(textOf(body, "NewInternalPort"))
	lease, _ := strconv.Atoi(textOf(body, "NewLeaseDuration"))
	return Mapping{
		ExtPort: ext, Proto: strings.ToLower(textOf(body, "NewProtocol")), Host: textOf(body, "NewInternalClient"),
		Port: port, Description: textOf(body, "NewPortMappingDescription"), Enabled: textOf(body, "NewEnabled") == "1",
		Lease: lease, RemoteHost: textOf(body, "NewRemoteHost"),
	}
}

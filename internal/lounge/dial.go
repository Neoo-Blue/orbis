package lounge

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DiscoveredScreen is a YouTube-capable device found on the LAN via DIAL.
type DiscoveredScreen struct {
	Name     string `json:"name"`
	Model    string `json:"model"`
	Location string `json:"location"` // device-description URL
	AppURL   string `json:"-"`        // DIAL Application-URL base
	Host     string `json:"host"`
	// ScreenID is the durable Lounge id, present only when the YouTube app is
	// running and the device exposes it over DIAL. When empty, the device must
	// be paired with a TV code instead.
	ScreenID string `json:"screen_id"`
	AppState string `json:"app_state"` // running | stopped | ""
}

// AutoPairable reports whether this screen can be adopted with no manual code.
func (d DiscoveredScreen) AutoPairable() bool { return d.ScreenID != "" }

const ssdpAddr = "239.255.255.250:1900"

// Discover performs an SSDP M-SEARCH for DIAL devices and enriches each hit
// with its friendly name and, if the YouTube app is exposing one, its screen
// id. It returns whatever it found within the window; a device that is powered
// off simply will not answer.
func Discover(ctx context.Context, window time.Duration) ([]DiscoveredScreen, error) {
	if window <= 0 {
		window = 3 * time.Second
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("ssdp socket: %w", err)
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return nil, err
	}
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + ssdpAddr + "\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
	// Send a couple of probes: UDP multicast is lossy.
	for i := 0; i < 2; i++ {
		if _, err := conn.WriteToUDP([]byte(msg), dst); err != nil {
			return nil, fmt.Errorf("ssdp send: %w", err)
		}
	}

	deadline := time.Now().Add(window)
	_ = conn.SetReadDeadline(deadline)

	locations := map[string]bool{}
	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			break
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // deadline reached
		}
		if loc := headerValue(string(buf[:n]), "LOCATION"); loc != "" {
			locations[loc] = true
		}
	}

	hc := &http.Client{Timeout: 5 * time.Second}
	var screens []DiscoveredScreen
	for loc := range locations {
		s, err := describe(ctx, hc, loc)
		if err != nil {
			continue
		}
		screens = append(screens, s)
	}
	return screens, nil
}

// describe fetches the device description and the YouTube DIAL app-info.
func describe(ctx context.Context, hc *http.Client, location string) (DiscoveredScreen, error) {
	s := DiscoveredScreen{Location: location, Host: hostOf(location)}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return s, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return s, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	appURL := resp.Header.Get("Application-URL")
	resp.Body.Close()

	var root struct {
		Device struct {
			FriendlyName string `xml:"friendlyName"`
			ModelName    string `xml:"modelName"`
		} `xml:"device"`
	}
	_ = xml.Unmarshal(body, &root)
	s.Name = strings.TrimSpace(root.Device.FriendlyName)
	s.Model = strings.TrimSpace(root.Device.ModelName)
	if s.Name == "" {
		s.Name = s.Host
	}

	if appURL == "" {
		return s, nil
	}
	if !strings.HasSuffix(appURL, "/") {
		appURL += "/"
	}
	s.AppURL = appURL

	// The YouTube app-info document carries the screen id when the app is
	// running and the device is willing to be linked by same-network devices.
	ytURL := appURL + "YouTube"
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, ytURL, nil)
	if err != nil {
		return s, nil
	}
	resp2, err := hc.Do(req2)
	if err != nil {
		return s, nil
	}
	appBody, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
	resp2.Body.Close()

	var app struct {
		State          string `xml:"state"`
		AdditionalData struct {
			ScreenID string `xml:"screenId"`
		} `xml:"additionalData"`
	}
	_ = xml.Unmarshal(appBody, &app)
	s.AppState = strings.TrimSpace(app.State)
	s.ScreenID = strings.TrimSpace(app.AdditionalData.ScreenID)
	return s, nil
}

func headerValue(raw, key string) string {
	key = strings.ToLower(key)
	for _, line := range strings.Split(raw, "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:i])) == key {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

func hostOf(rawurl string) string {
	rawurl = strings.TrimPrefix(rawurl, "http://")
	rawurl = strings.TrimPrefix(rawurl, "https://")
	if i := strings.IndexAny(rawurl, ":/"); i >= 0 {
		return rawurl[:i]
	}
	return rawurl
}

package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Container is the part of a Docker Engine container listing we use.
type Container struct {
	ID    string
	Name  string
	Image string
	State string
	Ports []ContainerPort
}

// ContainerPort is one published port.
type ContainerPort struct {
	IP          string
	PrivatePort int
	PublicPort  int
	Type        string
}

type rawContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
	Ports []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// dockerClient turns tcp://host:2375, http(s)://host:port or
// unix:///var/run/docker.sock into a base URL and a client that reaches it.
func dockerClient(raw string) (base string, host string, client *http.Client, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", nil, err
	}
	client = &http.Client{Timeout: 15 * time.Second}
	switch u.Scheme {
	case "unix":
		path := u.Path
		if path == "" {
			path = "/var/run/docker.sock"
		}
		client.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}
		return "http://docker", "", client, nil
	case "tcp", "http":
		hostport := u.Host
		if u.Port() == "" {
			hostport = net.JoinHostPort(u.Hostname(), "2375")
		}
		return "http://" + hostport, u.Hostname(), client, nil
	case "https":
		return "https://" + u.Host, u.Hostname(), client, nil
	}
	return "", "", nil, fmt.Errorf("docker url must start with tcp://, http://, https:// or unix://")
}

// ListContainers returns the running containers of one Docker host and the
// address services on it are reached at ("" for a unix socket, meaning this
// node itself).
func ListContainers(ctx context.Context, rawURL string) ([]Container, string, error) {
	base, host, client, err := dockerClient(rawURL)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1.24/containers/json", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, host, fmt.Errorf("docker api unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, host, fmt.Errorf("docker api returned http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var raws []rawContainer
	if err := json.Unmarshal(body, &raws); err != nil {
		return nil, host, fmt.Errorf("that is not a Docker Engine API (%v)", err)
	}
	out := make([]Container, 0, len(raws))
	for _, r := range raws {
		c := Container{ID: r.ID, Image: r.Image, State: r.State}
		if len(r.Names) > 0 {
			c.Name = strings.TrimPrefix(r.Names[0], "/")
		}
		for _, p := range r.Ports {
			c.Ports = append(c.Ports, ContainerPort{IP: p.IP, PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Type: p.Type})
		}
		out = append(out, c)
	}
	return out, host, nil
}

// DockerVersion is the connectivity test: engine version and container count.
func DockerVersion(ctx context.Context, rawURL string) (map[string]any, error) {
	base, _, client, err := dockerClient(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/version", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker api unreachable: %w", err)
	}
	defer resp.Body.Close()
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		Os         string `json:"Os"`
		Arch       string `json:"Arch"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &v) != nil || v.APIVersion == "" {
		return nil, fmt.Errorf("that address did not answer like a Docker Engine API (http %d)", resp.StatusCode)
	}
	containers, _, err := ListContainers(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "version": v.Version, "api_version": v.APIVersion, "os": v.Os, "arch": v.Arch, "containers": len(containers)}, nil
}

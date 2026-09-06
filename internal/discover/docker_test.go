package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListContainersParsesPublishedPorts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.24/containers/json":
			w.Write([]byte(`[{"Id":"abc","Names":["/jellyfin"],"Image":"jellyfin/jellyfin:latest","State":"running",
			  "Ports":[{"IP":"0.0.0.0","PrivatePort":8096,"PublicPort":8096,"Type":"tcp"},{"PrivatePort":1900,"Type":"udp"}]},
			 {"Id":"def","Names":["/db"],"Image":"postgres:16","State":"running","Ports":[{"IP":"127.0.0.1","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"}]}]`))
		case "/version":
			w.Write([]byte(`{"Version":"27.1.1","ApiVersion":"1.46","Os":"linux","Arch":"arm64"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cs, host, err := ListContainers(context.Background(), strings.Replace(srv.URL, "http://", "tcp://", 1))
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host = %q", host)
	}
	if len(cs) != 2 || cs[0].Name != "jellyfin" || cs[0].Ports[0].PublicPort != 8096 || cs[0].Ports[1].PublicPort != 0 {
		t.Errorf("containers = %+v", cs)
	}
	v, err := DockerVersion(context.Background(), srv.URL)
	if err != nil || v["api_version"] != "1.46" || v["containers"] != 2 {
		t.Errorf("version = %v, %v", v, err)
	}
	if _, err := DockerVersion(context.Background(), "ftp://x"); err == nil {
		t.Error("unsupported scheme should be refused")
	}
}

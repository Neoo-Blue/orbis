package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// A nil Go slice marshals to JSON `null`, and `null.length` in the browser
// throws — which unmounts the page. This is a whole class of bug that only
// shows up on a node where the thing in question has never been configured,
// so it is easy to miss in development and guaranteed to hit a fresh install.
//
// The rule is that any slice reaching the API is initialised. This test pins
// that for the shapes the UI iterates over.
func TestNoNilSlicesInAPIShapes(t *testing.T) {
	cases := map[string]any{
		"tailscale status": struct {
			Peers              []string `json:"peers"`
			AvailableExitNodes []string `json:"available_exit_nodes"`
			AdvertisedRoutes   []string `json:"advertised_routes"`
			ApprovedRoutes     []string `json:"approved_routes"`
			PendingRoutes      []string `json:"pending_routes"`
		}{
			Peers: []string{}, AvailableExitNodes: []string{},
			AdvertisedRoutes: []string{}, ApprovedRoutes: []string{}, PendingRoutes: []string{},
		},
	}
	for name, v := range cases {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "null") {
			t.Errorf("%s encodes a null where the UI expects an array: %s", name, raw)
		}
	}
}

// TestNilSliceMarshalsToNull documents the behaviour this guards against, so
// the reason for all the explicit initialisation is not mysterious later.
func TestNilSliceMarshalsToNull(t *testing.T) {
	var s []string
	raw, _ := json.Marshal(map[string]any{"routes": s})
	if string(raw) != `{"routes":null}` {
		t.Fatalf("expected a nil slice to encode as null, got %s", raw)
	}
	empty := []string{}
	raw, _ = json.Marshal(map[string]any{"routes": empty})
	if string(raw) != `{"routes":[]}` {
		t.Fatalf("expected an empty slice to encode as [], got %s", raw)
	}
}

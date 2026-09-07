package intercept

import (
	"encoding/json"
	"os"
	"time"
)

// Marker is what a running takeover writes to disk, so that a process that
// died without restoring its devices can be cleaned up after by something
// that did not share its memory: the release step systemd runs after every
// stop, and the lifeboat.
type Marker struct {
	Interface string            `json:"interface"`
	Gateway   string            `json:"gateway"`
	Clients   map[string]string `json:"clients"` // ip -> mac
	Since     time.Time         `json:"since"`
}

// WriteMarker records an active takeover; RemoveMarker clears it on a clean
// stop. ReadMarker returns nil when there is nothing to restore.
func WriteMarker(path string, m Marker) error {
	if path == "" {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func RemoveMarker(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

func ReadMarker(path string) (*Marker, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m Marker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

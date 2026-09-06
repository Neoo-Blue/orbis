package api

import "testing"

func TestWiFiQRPayload(t *testing.T) {
	got := wifiQRPayload("Orbis: home", `pa;ss"w,ord\`, true)
	want := `WIFI:T:WPA;S:Orbis\: home;P:pa\;ss\"w\,ord\\;H:true;;`
	if got != want {
		t.Errorf("payload = %q, want %q", got, want)
	}
	if wifiQRPayload("Orbis", "secret12", false) != "WIFI:T:WPA;S:Orbis;P:secret12;;" {
		t.Errorf("plain payload wrong: %q", wifiQRPayload("Orbis", "secret12", false))
	}
}

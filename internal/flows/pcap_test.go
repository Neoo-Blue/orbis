package flows

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestValidateBPFRejectsShellMetacharacters(t *testing.T) {
	for _, bad := range []string{"port 80; rm -rf /", "a | b", "$(id)", "x`y`", "a>b"} {
		if err := validateBPF(bad); err == nil {
			t.Errorf("filter %q should be rejected", bad)
		}
	}
	for _, good := range []string{"", "port 443", "host 1.1.1.1 and tcp", "not port 22"} {
		if err := validateBPF(good); err != nil {
			t.Errorf("filter %q should be accepted: %v", good, err)
		}
	}
}

func TestPcapHeaderIsWellFormed(t *testing.T) {
	var buf bytes.Buffer
	if err := writePcapHeader(&buf, 262); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) != 24 {
		t.Fatalf("pcap global header must be 24 bytes, got %d", len(b))
	}
	if got := binary.LittleEndian.Uint32(b[0:4]); got != pcapMagic {
		t.Fatalf("bad magic %x", got)
	}
	if got := binary.LittleEndian.Uint32(b[16:20]); got != 262 {
		t.Fatalf("snaplen not recorded, got %d", got)
	}
	if got := binary.LittleEndian.Uint32(b[20:24]); got != linkEthernet {
		t.Fatalf("link type should be ethernet, got %d", got)
	}
}

func TestPcapPacketRecordsOriginalLength(t *testing.T) {
	var buf bytes.Buffer
	// A truncated capture must still report the real on-wire length, or
	// analysis tools misreport every packet.
	data := []byte{1, 2, 3, 4}
	if err := writePcapPacket(&buf, time.Unix(1000, 500000), data, 1500); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if binary.LittleEndian.Uint32(b[0:4]) != 1000 {
		t.Error("timestamp seconds wrong")
	}
	if binary.LittleEndian.Uint32(b[4:8]) != 500 {
		t.Error("timestamp microseconds wrong")
	}
	if binary.LittleEndian.Uint32(b[8:12]) != 4 {
		t.Error("captured length wrong")
	}
	if binary.LittleEndian.Uint32(b[12:16]) != 1500 {
		t.Error("original length wrong")
	}
}

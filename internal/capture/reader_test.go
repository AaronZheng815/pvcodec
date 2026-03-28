package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestReadFilePCAPNG(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.pcapng")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcapng: %v", err)
	}

	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("new pcapng writer: %v", err)
	}
	packet := []byte{0, 1, 2, 3, 4, 5}
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Unix(1, 0),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush pcapng: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close pcapng: %v", err)
	}

	packets, err := ReadFile(path)
	if err != nil {
		t.Fatalf("read pcapng: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].LinkType != layers.LinkTypeEthernet {
		t.Fatalf("unexpected link type: %v", packets[0].LinkType)
	}
}

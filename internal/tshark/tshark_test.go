package tshark

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

type fakeRunner struct {
	outputs map[string][]byte
	err     error
}

func (f *fakeRunner) Output(name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	for prefix, out := range f.outputs {
		if strings.Contains(key, prefix) {
			if f.err != nil {
				return out, f.err
			}
			return out, nil
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return nil, fmt.Errorf("no fake output for: %s", key)
}

func TestUnavailable(t *testing.T) {
	ts := &TShark{runner: &fakeRunner{}}
	if ts.Available() {
		t.Fatal("expected unavailable")
	}
	if v := ts.Version(); v != "" {
		t.Fatalf("expected empty version, got %q", v)
	}
	_, err := ts.ListPackets("/tmp/test.pcap", "")
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("expected not-installed error, got %v", err)
	}
	_, err = ts.PacketDetail("/tmp/test.pcap", 1)
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("expected not-installed error, got %v", err)
	}
}

func TestVersion(t *testing.T) {
	ts := NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"--version": []byte("TShark (Wireshark) 4.2.5\nmore lines\n"),
		},
	})
	v := ts.Version()
	if v != "TShark (Wireshark) 4.2.5" {
		t.Fatalf("unexpected version: %q", v)
	}
}

func TestDiscoverTSharkPathFromEnv(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "fake-tshark-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	original := os.Getenv("PVCODEC_TSHARK_PATH")
	t.Cleanup(func() {
		if original == "" {
			_ = os.Unsetenv("PVCODEC_TSHARK_PATH")
			return
		}
		_ = os.Setenv("PVCODEC_TSHARK_PATH", original)
	})

	if err := os.Setenv("PVCODEC_TSHARK_PATH", tmpFile.Name()); err != nil {
		t.Fatal(err)
	}

	if got := discoverTSharkPath(); got != tmpFile.Name() {
		t.Fatalf("discoverTSharkPath() = %q, want %q", got, tmpFile.Name())
	}
}

func TestListPackets(t *testing.T) {
	tsharkOutput := strings.Join([]string{
		"1\t1711612800.000000\t10.0.0.1\t\t10.0.0.2\t\tNGAP\t120\tInitialUEMessage",
		"2\t1711612801.000000\t10.0.0.2\t\t10.0.0.1\t\tNGAP\t200\tDownlinkNASTransport",
		"3\t1711612802.000000\t10.0.0.3\t\t10.0.0.4\t\tDiameter\t300\tCapabilities-Exchange-Request",
	}, "\n") + "\n"

	ts := NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T fields": []byte(tsharkOutput),
		},
	})

	packets, err := ts.ListPackets("/tmp/test.pcap", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}

	if packets[0].Index != 1 || packets[0].SrcAddr != "10.0.0.1" || packets[0].Protocol != "NGAP" {
		t.Fatalf("packet 0 mismatch: %+v", packets[0])
	}
	if packets[2].Protocol != "Diameter" || packets[2].Length != 300 {
		t.Fatalf("packet 2 mismatch: %+v", packets[2])
	}
}

func TestListPacketsIPv6(t *testing.T) {
	tsharkOutput := "1\t1711612800.000000\t\t::1\t\t::2\tICMPv6\t80\tEcho Request\n"

	ts := NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T fields": []byte(tsharkOutput),
		},
	})

	packets, err := ts.ListPackets("/tmp/test.pcap", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].SrcAddr != "::1" || packets[0].DstAddr != "::2" {
		t.Fatalf("IPv6 address mismatch: src=%q dst=%q", packets[0].SrcAddr, packets[0].DstAddr)
	}
}

func TestListPacketsAllowsCutShortWarning(t *testing.T) {
	tsharkOutput := "1\t1711612800.000000\t10.0.0.1\t\t10.0.0.2\t\tNGAP\t120\tInitialUEMessage\n"

	ts := NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T fields": []byte(tsharkOutput),
		},
		err: fmt.Errorf("The file appears to have been cut short in the middle of a packet"),
	})

	packets, err := ts.ListPackets("/tmp/test.pcap", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 || packets[0].Protocol != "NGAP" {
		t.Fatalf("unexpected packets: %+v", packets)
	}
}

func TestPacketDetail(t *testing.T) {
	pdmlOutput := `<?xml version="1.0"?>
<pdml>
  <packet>
    <proto name="geninfo" showname="General information">
      <field name="num" showname="Number" show="1"/>
    </proto>
    <proto name="frame" showname="Frame 1: Packet, 120 bytes on wire">
      <field name="frame.number" showname="Frame Number: 1" show="1"/>
    </proto>
    <proto name="ngap" showname="NG Application Protocol">
      <field name="ngap.pLMNIdentity" showname="pLMNIdentity: 64f000" show="64:f0:00">
        <field name="e212.mcc" showname="Mobile Country Code (MCC): China (460)" show="460"/>
        <field name="e212.mnc" showname="Mobile Network Code (MNC): China Mobile (00)" show="00"/>
      </field>
    </proto>
  </packet>
</pdml>`

	ts := NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T pdml": []byte(pdmlOutput),
		},
	})

	detail, err := ts.PacketDetail("/tmp/test.pcap", 1)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Index != 1 {
		t.Fatalf("expected index 1, got %d", detail.Index)
	}
	if len(detail.Layers) == 0 {
		t.Fatal("expected non-empty layers")
	}

	layerNames := make(map[string]bool)
	for _, l := range detail.Layers {
		layerNames[l.Name] = true
	}
	for _, want := range []string{"frame", "ngap"} {
		if !layerNames[want] {
			t.Errorf("missing layer: %s", want)
		}
	}

	ngapFound := false
	mccFound := false
	for _, layer := range detail.Layers {
		if layer.Name != "ngap" {
			continue
		}
		ngapFound = true
		for _, child := range layer.Children {
			if child.Name == "pLMNIdentity" {
				for _, grandChild := range child.Children {
					if grandChild.Name == "Mobile Country Code (MCC)" && grandChild.Value == "China (460)" {
						mccFound = true
					}
				}
			}
		}
	}
	if !ngapFound {
		t.Fatal("expected ngap layer")
	}
	if !mccFound {
		t.Fatal("expected MCC display value in parsed PDML tree")
	}
}

func TestPacketDetailAllowsCutShortWarning(t *testing.T) {
	pdmlOutput := `<?xml version="1.0"?><pdml><packet><proto name="frame" showname="Frame 1"><field name="frame.number" showname="Frame Number: 1" show="1"/></proto></packet></pdml>`

	ts := NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T pdml": []byte(pdmlOutput),
		},
		err: fmt.Errorf("The file appears to have been cut short in the middle of a packet"),
	})

	detail, err := ts.PacketDetail("/tmp/test.pcap", 1)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Index != 1 {
		t.Fatalf("expected index 1, got %d", detail.Index)
	}
}

func TestDisplayFilter(t *testing.T) {
	tests := []struct {
		protocol string
		want     string
	}{
		{"NGAP", "ngap"},
		{"NAS", "nas-5gs"},
		{"Diameter", "diameter"},
		{"GTP", "gtp || gtpv2"},
		{"All", ""},
		{"", ""},
		{"DNS", "dns"},
	}
	for _, tt := range tests {
		got := DisplayFilter(tt.protocol)
		if got != tt.want {
			t.Errorf("DisplayFilter(%q) = %q, want %q", tt.protocol, got, tt.want)
		}
	}
}

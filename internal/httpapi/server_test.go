package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	gtpv2message "github.com/wmnsk/go-gtp/gtpv2/message"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

func TestServerUploadAndDecode(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "sample.pcap")
	if err := writeSamplePCAP(pcapPath); err != nil {
		t.Fatalf("write sample pcap: %v", err)
	}

	server := NewServer(t.TempDir())

	uploadRecorder := httptest.NewRecorder()
	uploadRequest := newUploadRequest(t, pcapPath)
	server.ServeHTTP(uploadRecorder, uploadRequest)
	if uploadRecorder.Code != http.StatusCreated {
		t.Fatalf("unexpected upload status: %d body=%s", uploadRecorder.Code, uploadRecorder.Body.String())
	}

	var uploadResponse struct {
		ID      string                `json:"id"`
		Packets []model.PacketSummary `json:"packets"`
	}
	if err := json.Unmarshal(uploadRecorder.Body.Bytes(), &uploadResponse); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if len(uploadResponse.Packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(uploadResponse.Packets))
	}

	var ngapPacket model.PacketSummary
	var gtpPacket model.PacketSummary
	var diameterPacket model.PacketSummary
	for _, packet := range uploadResponse.Packets {
		switch packet.Protocol {
		case model.ProtocolNGAP:
			ngapPacket = packet
		case model.ProtocolGTP:
			gtpPacket = packet
		case model.ProtocolDiameter:
			diameterPacket = packet
		}
	}

	if ngapPacket.Index == 0 || gtpPacket.Index == 0 || diameterPacket.Index == 0 {
		t.Fatalf("expected NGAP, GTP and Diameter packets in upload response: %+v", uploadResponse.Packets)
	}
	if !slices.Contains(ngapPacket.Protocols, model.ProtocolNAS) {
		t.Fatalf("expected NGAP packet to advertise embedded NAS, got %+v", ngapPacket.Protocols)
	}

	filterRecorder := httptest.NewRecorder()
	filterRequest := httptest.NewRequest(http.MethodGet, "/api/captures/"+uploadResponse.ID+"/packets?protocol=NAS", nil)
	server.ServeHTTP(filterRecorder, filterRequest)
	if filterRecorder.Code != http.StatusOK {
		t.Fatalf("unexpected list status: %d body=%s", filterRecorder.Code, filterRecorder.Body.String())
	}

	var filterResponse struct {
		Packets []model.PacketSummary `json:"packets"`
	}
	if err := json.Unmarshal(filterRecorder.Body.Bytes(), &filterResponse); err != nil {
		t.Fatalf("decode filter response: %v", err)
	}
	if len(filterResponse.Packets) != 1 || filterResponse.Packets[0].Index != ngapPacket.Index {
		t.Fatalf("unexpected NAS filter response: %+v", filterResponse.Packets)
	}

	detailRecorder := httptest.NewRecorder()
	detailRequest := httptest.NewRequest(http.MethodGet, "/api/captures/"+uploadResponse.ID+"/packets/"+stringIndex(ngapPacket.Index), nil)
	server.ServeHTTP(detailRecorder, detailRequest)
	if detailRecorder.Code != http.StatusOK {
		t.Fatalf("unexpected detail status: %d body=%s", detailRecorder.Code, detailRecorder.Body.String())
	}

	var detail model.PacketDetail
	if err := json.Unmarshal(detailRecorder.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if detail.DecodeInfo == "" {
		t.Fatalf("expected decode info in packet detail")
	}
	if !hasNodeNamed(detail.Layers, "NGAP") {
		t.Fatalf("expected NGAP tree node, got %+v", detail.Layers)
	}
	if !hasNodeNamed(detail.Layers, "Embedded NAS #1") {
		t.Fatalf("expected embedded NAS node, got %+v", detail.Layers)
	}
}

func newUploadRequest(t *testing.T, filePath string) *http.Request {
	t.Helper()
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		t.Fatalf("copy upload body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/captures", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func writeSamplePCAP(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}

	packets, err := samplePackets()
	if err != nil {
		return err
	}
	for i, packet := range packets {
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(i+1), 0),
			CaptureLength: len(packet),
			Length:        len(packet),
		}, packet); err != nil {
			return err
		}
	}
	return nil
}

func samplePackets() ([][]byte, error) {
	gtpPayload, err := gtpv2message.NewEchoRequest(1).Marshal()
	if err != nil {
		return nil, err
	}
	gtpPacket, err := buildUDPPacket(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 35000, 2123, gtpPayload)
	if err != nil {
		return nil, err
	}

	diameterPayload, err := buildDiameterPayload()
	if err != nil {
		return nil, err
	}
	diameterPacket, err := buildTCPPacket(net.IPv4(10, 0, 0, 3), net.IPv4(10, 0, 0, 4), 41000, 3868, diameterPayload)
	if err != nil {
		return nil, err
	}

	ngapPacket, err := buildSCTPPacket(net.IPv4(10, 0, 0, 5), net.IPv4(10, 0, 0, 6), 49000, 38412, sampleNGAPPayload())
	if err != nil {
		return nil, err
	}

	return [][]byte{gtpPacket, diameterPacket, ngapPacket}, nil
}

func buildDiameterPayload() ([]byte, error) {
	message := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
	if _, err := message.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("pvcodec.local")); err != nil {
		return nil, err
	}
	if _, err := message.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("local")); err != nil {
		return nil, err
	}
	return message.Serialize()
}

func buildUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	return serializeLayers(eth, ip, udp, gopacket.Payload(payload))
}

func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		DstMAC:       net.HardwareAddr{0x20, 0x21, 0x22, 0x23, 0x24, 0x25},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		PSH:     true,
		ACK:     true,
		Seq:     1,
		Ack:     1,
		Window:  8192,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	return serializeLayers(eth, ip, tcp, gopacket.Payload(payload))
}

func buildSCTPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x30, 0x31, 0x32, 0x33, 0x34, 0x35},
		DstMAC:       net.HardwareAddr{0x40, 0x41, 0x42, 0x43, 0x44, 0x45},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolSCTP,
	}
	sctp := &layers.SCTP{
		SrcPort:         layers.SCTPPort(srcPort),
		DstPort:         layers.SCTPPort(dstPort),
		VerificationTag: 1,
	}
	chunk := &layers.SCTPData{
		SCTPChunk: layers.SCTPChunk{
			Type: layers.SCTPChunkTypeData,
		},
		BeginFragment:   true,
		EndFragment:     true,
		TSN:             1,
		StreamId:        1,
		StreamSequence:  1,
		PayloadProtocol: 60,
	}
	return serializeLayers(eth, ip, sctp, chunk, gopacket.Payload(payload))
}

func serializeLayers(layersToSerialize ...gopacket.SerializableLayer) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, layersToSerialize...); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func hasNodeNamed(nodes []model.TreeNode, name string) bool {
	for _, node := range nodes {
		if node.Name == name {
			return true
		}
		if hasNodeNamed(node.Children, name) {
			return true
		}
	}
	return false
}

func sampleNGAPPayload() []byte {
	return []byte{
		0x0, 0xf, 0x40, 0x57, 0x0, 0x0, 0x6, 0x0, 0x55, 0x0, 0x5, 0xc0, 0xce, 0x0, 0x0,
		0x0, 0x0, 0x26, 0x0, 0x23, 0x22, 0x7e, 0x0, 0x41, 0x79, 0x0, 0xd, 0x1, 0x13, 0x0, 0x13,
		0xf, 0xff, 0x0, 0x0, 0x41, 0x0, 0x0, 0x21, 0xf0, 0x2e, 0x4, 0x80, 0x20, 0xe0, 0xe0, 0x17,
		0x7, 0xe0, 0xe0, 0xc0, 0x40, 0x0, 0x80, 0x20, 0x0, 0x79, 0x0, 0xf, 0x40, 0x13, 0x30, 0x1,
		0x0, 0x0, 0x0, 0x0, 0x10, 0x13, 0x30, 0x1, 0x0, 0x0, 0x1, 0x0, 0x5a, 0x40, 0x1, 0x18, 0x0,
		0x70, 0x40, 0x1, 0x0, 0x0, 0xae, 0x40, 0x3, 0x64, 0xf6, 0x66,
	}
}

func stringIndex(v int) string {
	return strconv.Itoa(v)
}

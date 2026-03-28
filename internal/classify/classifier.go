package classify

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/AaronZheng815/pvcodec/internal/capture"
	"github.com/AaronZheng815/pvcodec/internal/decode"
	"github.com/AaronZheng815/pvcodec/internal/model"
)

const ngapPPID layers.SCTPPayloadProtocol = 60

type InspectedPacket struct {
	Summary  model.PacketSummary
	Payload  []byte
	Packet   gopacket.Packet
	Protocol model.Protocol
}

func Inspect(raw capture.RawPacket, registry *decode.Registry) (InspectedPacket, error) {
	packet := gopacket.NewPacket(raw.Data, raw.LinkType, gopacket.DecodeOptions{
		Lazy:                     false,
		NoCopy:                   true,
		DecodeStreamsAsDatagrams: true,
	})

	summary := model.PacketSummary{
		Index:     raw.Index,
		Timestamp: raw.Timestamp,
		Protocol:  model.ProtocolUnknown,
		Protocols: []model.Protocol{model.ProtocolUnknown},
		Length:    raw.OriginalLength,
		Info:      "Unclassified packet",
	}

	var srcAddr, dstAddr string
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		srcAddr = ipv4.SrcIP.String()
		dstAddr = ipv4.DstIP.String()
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		srcAddr = ipv6.SrcIP.String()
		dstAddr = ipv6.DstIP.String()
	}
	summary.SrcAddr = srcAddr
	summary.DstAddr = dstAddr

	var payload []byte
	if sctpLayer := packet.Layer(layers.LayerTypeSCTP); sctpLayer != nil {
		sctp := sctpLayer.(*layers.SCTP)
		summary.SrcPort = uint16(sctp.SrcPort)
		summary.DstPort = uint16(sctp.DstPort)
		summary.Protocol = model.ProtocolSCTP
		summary.Protocols = []model.Protocol{model.ProtocolSCTP}
		summary.Info = fmt.Sprintf("SCTP %d -> %d", sctp.SrcPort, sctp.DstPort)

		if dataLayer := packet.Layer(layers.LayerTypeSCTPData); dataLayer != nil {
			chunk := dataLayer.(*layers.SCTPData)
			payload = append([]byte(nil), chunk.LayerPayload()...)
			if chunk.PayloadProtocol == ngapPPID || uint16(sctp.SrcPort) == 38412 || uint16(sctp.DstPort) == 38412 {
				summary.Protocol = model.ProtocolNGAP
				summary.Protocols = []model.Protocol{model.ProtocolNGAP}
				summary.Info = fmt.Sprintf("NGAP PPID=%d", chunk.PayloadProtocol)
				if registry != nil && len(payload) > 0 {
					if result, err := registry.Decode(model.ProtocolNGAP, payload); err == nil && len(result.Embedded[model.ProtocolNAS]) > 0 {
						summary.Protocols = append(summary.Protocols, model.ProtocolNAS)
						summary.Info = "NGAP with NAS-PDU"
					}
				}
			}
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		summary.SrcPort = uint16(udp.SrcPort)
		summary.DstPort = uint16(udp.DstPort)
		payload = append([]byte(nil), udp.Payload...)
		summary.Protocol = model.ProtocolUDP
		summary.Protocols = []model.Protocol{model.ProtocolUDP}
		summary.Info = fmt.Sprintf("UDP %d -> %d", udp.SrcPort, udp.DstPort)
		if isGTPPort(summary.SrcPort) || isGTPPort(summary.DstPort) {
			summary.Protocol = model.ProtocolGTP
			summary.Protocols = []model.Protocol{model.ProtocolGTP}
			summary.Info = "GTP tunnel/control message"
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		summary.SrcPort = uint16(tcp.SrcPort)
		summary.DstPort = uint16(tcp.DstPort)
		payload = append([]byte(nil), tcp.Payload...)
		summary.Protocol = model.ProtocolTCP
		summary.Protocols = []model.Protocol{model.ProtocolTCP}
		summary.Info = fmt.Sprintf("TCP %d -> %d", tcp.SrcPort, tcp.DstPort)
		if summary.SrcPort == 3868 || summary.DstPort == 3868 {
			summary.Protocol = model.ProtocolDiameter
			summary.Protocols = []model.Protocol{model.ProtocolDiameter}
			summary.Info = "Diameter signaling"
		}
	}

	if summary.Protocol == model.ProtocolUnknown && len(payload) > 0 && registry != nil {
		if _, err := registry.Decode(model.ProtocolNAS, payload); err == nil {
			summary.Protocol = model.ProtocolNAS
			summary.Protocols = []model.Protocol{model.ProtocolNAS}
			summary.Info = "Standalone NAS-5GS"
		}
	}

	if summary.Info == "" {
		summary.Info = strings.ToUpper(hex.EncodeToString(payload))
	}

	return InspectedPacket{
		Summary:  summary,
		Payload:  payload,
		Packet:   packet,
		Protocol: summary.Protocol,
	}, nil
}

func isGTPPort(port uint16) bool {
	switch port {
	case 2123, 2152, 3386:
		return true
	default:
		return false
	}
}

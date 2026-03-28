package model

import "time"

type Protocol string

const (
	ProtocolNGAP     Protocol = "NGAP"
	ProtocolNAS      Protocol = "NAS"
	ProtocolDiameter Protocol = "Diameter"
	ProtocolGTP      Protocol = "GTP"
	ProtocolSCTP     Protocol = "SCTP"
	ProtocolTCP      Protocol = "TCP"
	ProtocolUDP      Protocol = "UDP"
	ProtocolUnknown  Protocol = "Unknown"
)

type PacketSummary struct {
	Index     int        `json:"index"`
	Timestamp time.Time  `json:"timestamp"`
	SrcAddr   string     `json:"srcAddr"`
	DstAddr   string     `json:"dstAddr"`
	SrcPort   uint16     `json:"srcPort,omitempty"`
	DstPort   uint16     `json:"dstPort,omitempty"`
	Protocol  Protocol   `json:"protocol"`
	Protocols []Protocol `json:"protocols,omitempty"`
	Length    int        `json:"length"`
	Info      string     `json:"info"`
}

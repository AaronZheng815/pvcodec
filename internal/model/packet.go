package model

type PacketSummary struct {
	Index    int    `json:"index"`
	SrcAddr  string `json:"srcAddr"`
	DstAddr  string `json:"dstAddr"`
	Protocol string `json:"protocol"`
	Length   int    `json:"length"`
	Info     string `json:"info"`
}

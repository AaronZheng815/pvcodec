package model

type TreeNode struct {
	Name     string     `json:"name"`
	Value    string     `json:"value,omitempty"`
	RawHex   string     `json:"rawHex,omitempty"`
	Error    string     `json:"error,omitempty"`
	Children []TreeNode `json:"children,omitempty"`
}

type PacketDetail struct {
	Index      int           `json:"index"`
	Summary    PacketSummary `json:"summary"`
	Layers     []TreeNode    `json:"layers"`
	RawHex     string        `json:"rawHex"`
	DecodeInfo string        `json:"decodeInfo,omitempty"`
}

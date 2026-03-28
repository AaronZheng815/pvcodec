package decode

import (
	"encoding/hex"

	"github.com/free5gc/nas"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

type NASDecoder struct{}

func (NASDecoder) Name() model.Protocol {
	return model.ProtocolNAS
}

func (NASDecoder) Decode(data []byte) (Result, error) {
	msg := nas.NewMessage()
	buf := append([]byte(nil), data...)
	if err := msg.PlainNasDecode(&buf); err != nil {
		return Result{}, err
	}

	return Result{
		Info:   "NAS-5GS",
		Nodes:  []model.TreeNode{BuildTree("NAS-5GS", msg)},
		RawHex: hex.EncodeToString(data),
	}, nil
}

package decode

import (
	"bytes"
	"encoding/hex"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/dict"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

type DiameterDecoder struct{}

func (DiameterDecoder) Name() model.Protocol {
	return model.ProtocolDiameter
}

func (DiameterDecoder) Decode(data []byte) (Result, error) {
	msg, err := diam.ReadMessage(bytes.NewReader(data), dict.Default)
	if err != nil {
		return Result{}, err
	}

	info := "Diameter"
	if msg.Header != nil {
		info = msg.Header.String()
	}
	return Result{
		Info:   info,
		Nodes:  []model.TreeNode{BuildTree("Diameter", msg)},
		RawHex: hex.EncodeToString(data),
	}, nil
}

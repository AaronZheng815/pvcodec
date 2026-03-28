package decode

import (
	"encoding/hex"
	"fmt"

	gtpv1message "github.com/wmnsk/go-gtp/gtpv1/message"
	gtpv2message "github.com/wmnsk/go-gtp/gtpv2/message"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

type GTPDecoder struct{}

func (GTPDecoder) Name() model.Protocol {
	return model.ProtocolGTP
}

func (GTPDecoder) Decode(data []byte) (Result, error) {
	if len(data) == 0 {
		return Result{}, fmt.Errorf("empty GTP payload")
	}

	if msg, err := gtpv2message.Parse(data); err == nil {
		info := "GTPv2"
		if named, ok := msg.(interface{ MessageTypeName() string }); ok {
			info = named.MessageTypeName()
		}
		return Result{
			Info:   info,
			Nodes:  []model.TreeNode{BuildTree("GTPv2", msg)},
			RawHex: hex.EncodeToString(data),
		}, nil
	}

	msg, err := gtpv1message.Parse(data)
	if err != nil {
		return Result{}, err
	}
	info := "GTPv1"
	if named, ok := msg.(interface{ MessageTypeName() string }); ok {
		info = named.MessageTypeName()
	}
	return Result{
		Info:   info,
		Nodes:  []model.TreeNode{BuildTree("GTPv1", msg)},
		RawHex: hex.EncodeToString(data),
	}, nil
}

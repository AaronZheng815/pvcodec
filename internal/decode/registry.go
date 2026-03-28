package decode

import "github.com/AaronZheng815/pvcodec/internal/model"

type Result struct {
	Info     string
	Nodes    []model.TreeNode
	Embedded map[model.Protocol][][]byte
	RawHex   string
	Fallback bool
}

type Decoder interface {
	Name() model.Protocol
	Decode(data []byte) (Result, error)
}

type Registry struct {
	decoders map[model.Protocol]Decoder
}

func NewRegistry() *Registry {
	return &Registry{decoders: make(map[model.Protocol]Decoder)}
}

func (r *Registry) Register(d Decoder) {
	r.decoders[d.Name()] = d
}

func (r *Registry) Get(p model.Protocol) (Decoder, bool) {
	d, ok := r.decoders[p]
	return d, ok
}

func (r *Registry) Decode(protocol model.Protocol, data []byte) (Result, error) {
	decoder, ok := r.Get(protocol)
	if !ok {
		return Result{}, ErrDecoderNotFound{Protocol: protocol}
	}
	return decoder.Decode(data)
}

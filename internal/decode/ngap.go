package decode

import (
	"encoding/hex"
	"reflect"
	"strings"

	"github.com/free5gc/ngap"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

type NGAPDecoder struct{}

func (NGAPDecoder) Name() model.Protocol {
	return model.ProtocolNGAP
}

func (NGAPDecoder) Decode(data []byte) (Result, error) {
	pdu, err := ngap.Decoder(data)
	if err != nil {
		return Result{}, err
	}

	embedded := map[model.Protocol][][]byte{}
	if nasPayloads := collectNASPayloads(reflect.ValueOf(pdu)); len(nasPayloads) > 0 {
		embedded[model.ProtocolNAS] = nasPayloads
	}

	return Result{
		Info:     "NGAP",
		Nodes:    []model.TreeNode{BuildTree("NGAP", pdu)},
		Embedded: embedded,
		RawHex:   hex.EncodeToString(data),
	}, nil
}

func collectNASPayloads(v reflect.Value) [][]byte {
	var payloads [][]byte
	var walk func(reflect.Value)
	walk = func(current reflect.Value) {
		if !current.IsValid() {
			return
		}
		for current.Kind() == reflect.Interface || current.Kind() == reflect.Pointer {
			if current.IsNil() {
				return
			}
			current = current.Elem()
		}

		switch current.Kind() {
		case reflect.Struct:
			typeName := current.Type().Name()
			if strings.Contains(typeName, "NASPDU") {
				field := current.FieldByName("Value")
				if field.IsValid() && field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8 && field.Len() > 0 {
					payloads = append(payloads, append([]byte(nil), field.Bytes()...))
				}
			}
			for i := range current.NumField() {
				walk(current.Field(i))
			}
		case reflect.Slice, reflect.Array:
			if current.Type().Elem().Kind() == reflect.Uint8 {
				return
			}
			for i := range current.Len() {
				walk(current.Index(i))
			}
		case reflect.Map:
			for _, key := range current.MapKeys() {
				walk(current.MapIndex(key))
			}
		}
	}
	walk(v)
	return payloads
}

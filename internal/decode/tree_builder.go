package decode

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

const maxHexPreview = 64

func BuildTree(name string, value any) model.TreeNode {
	return buildValueNode(name, reflect.ValueOf(value), 0)
}

func buildValueNode(name string, v reflect.Value, depth int) model.TreeNode {
	node := model.TreeNode{Name: name}
	if !v.IsValid() {
		node.Value = "nil"
		return node
	}
	if depth > 8 {
		node.Value = "<max depth>"
		return node
	}

	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			node.Value = "nil"
			return node
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Bool:
		node.Value = fmt.Sprintf("%t", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		node.Value = fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		node.Value = fmt.Sprintf("%d", v.Uint())
	case reflect.Float32, reflect.Float64:
		node.Value = fmt.Sprintf("%f", v.Float())
	case reflect.String:
		node.Value = v.String()
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := append([]byte(nil), v.Bytes()...)
			node.Value = formatByteSlice(b)
			node.RawHex = hex.EncodeToString(b)
			return node
		}
		for i := range v.Len() {
			node.Children = append(node.Children, buildValueNode(fmt.Sprintf("[%d]", i), v.Index(i), depth+1))
		}
		node.Value = fmt.Sprintf("%d item(s)", v.Len())
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range v.Len() {
				b[i] = byte(v.Index(i).Uint())
			}
			node.Value = formatByteSlice(b)
			node.RawHex = hex.EncodeToString(b)
			return node
		}
		for i := range v.Len() {
			node.Children = append(node.Children, buildValueNode(fmt.Sprintf("[%d]", i), v.Index(i), depth+1))
		}
		node.Value = fmt.Sprintf("%d item(s)", v.Len())
	case reflect.Struct:
		for i := range v.NumField() {
			field := v.Type().Field(i)
			if field.PkgPath != "" {
				continue
			}
			node.Children = append(node.Children, buildValueNode(field.Name, v.Field(i), depth+1))
		}
	case reflect.Map:
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface())
		})
		for _, key := range keys {
			node.Children = append(node.Children, buildValueNode(fmt.Sprint(key.Interface()), v.MapIndex(key), depth+1))
		}
		node.Value = fmt.Sprintf("%d item(s)", len(keys))
	default:
		node.Value = fmt.Sprint(v.Interface())
	}

	if node.Value == "" && len(node.Children) > 0 {
		node.Value = fmt.Sprintf("%d field(s)", len(node.Children))
	}
	return node
}

func formatByteSlice(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}
	hexText := hex.EncodeToString(data)
	if len(data) > maxHexPreview {
		return strings.ToUpper(hexText[:maxHexPreview*2]) + "..."
	}
	return strings.ToUpper(hexText)
}

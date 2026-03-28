package tshark

import (
	"fmt"
	"sort"
	"strings"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

func jsonMapToTree(layers map[string]any) []model.TreeNode {
	if layers == nil {
		return nil
	}

	keys := make([]string, 0, len(layers))
	for k := range layers {
		if strings.HasSuffix(k, "_raw") || strings.HasPrefix(k, "_ws.") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	nodes := make([]model.TreeNode, 0, len(keys))
	for _, key := range keys {
		nodes = append(nodes, jsonValueToNode(key, layers[key]))
	}
	return nodes
}

func jsonValueToNode(name string, value any) model.TreeNode {
	node := model.TreeNode{Name: name}

	switch v := value.(type) {
	case map[string]any:
		children := make([]string, 0, len(v))
		for k := range v {
			if strings.HasSuffix(k, "_raw") {
				continue
			}
			children = append(children, k)
		}
		sort.Strings(children)
		for _, k := range children {
			node.Children = append(node.Children, jsonValueToNode(k, v[k]))
		}
	case []any:
		if len(v) == 1 {
			return jsonValueToNode(name, v[0])
		}
		for i, item := range v {
			node.Children = append(node.Children, jsonValueToNode(fmt.Sprintf("[%d]", i), item))
		}
	case string:
		node.Value = v
	case float64:
		node.Value = fmt.Sprintf("%g", v)
	case bool:
		node.Value = fmt.Sprintf("%t", v)
	case nil:
		node.Value = ""
	default:
		node.Value = fmt.Sprint(v)
	}

	return node
}

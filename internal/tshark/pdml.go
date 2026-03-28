package tshark

import (
	"bytes"
	"encoding/xml"
	"html"
	"sort"
	"strings"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

type pdmlDocument struct {
	Packets []pdmlPacket `xml:"packet"`
}

type pdmlPacket struct {
	Protos []pdmlElement `xml:"proto"`
}

type pdmlElement struct {
	Name     string        `xml:"name,attr"`
	Showname string        `xml:"showname,attr"`
	Show     string        `xml:"show,attr"`
	Value    string        `xml:"value,attr"`
	Hide     string        `xml:"hide,attr"`
	Fields   []pdmlElement `xml:"field"`
	Protos   []pdmlElement `xml:"proto"`
}

func parsePDMLDetail(data []byte, frameNumber int) (model.PacketDetail, error) {
	var doc pdmlDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return model.PacketDetail{}, err
	}
	if len(doc.Packets) == 0 {
		return model.PacketDetail{}, nil
	}

	layers := make([]model.TreeNode, 0, len(doc.Packets[0].Protos))
	for _, proto := range doc.Packets[0].Protos {
		if node, ok := pdmlElementToNode(proto, true); ok {
			layers = append(layers, node)
		}
	}
	layers = enrichProtocolLayers(layers)

	return model.PacketDetail{
		Index:  frameNumber,
		Layers: layers,
	}, nil
}

func pdmlElementToNode(element pdmlElement, topLevel bool) (model.TreeNode, bool) {
	if shouldSkipPDMLElement(element, topLevel) {
		return model.TreeNode{}, false
	}

	name, value := pdmlLabel(element, topLevel)
	if name == "" && value == "" {
		return model.TreeNode{}, false
	}

	node := model.TreeNode{
		Name:  name,
		Value: value,
	}

	for _, proto := range element.Protos {
		if child, ok := pdmlElementToNode(proto, false); ok {
			node.Children = append(node.Children, child)
		}
	}
	for _, field := range element.Fields {
		if child, ok := pdmlElementToNode(field, false); ok {
			node.Children = append(node.Children, child)
		}
	}

	if len(node.Children) == 0 && node.Value == "" {
		if raw := cleanPDMLText(element.Show); raw != "" && raw != node.Name {
			node.Value = raw
		}
	}

	return node, true
}

func shouldSkipPDMLElement(element pdmlElement, topLevel bool) bool {
	if element.Hide == "yes" {
		return true
	}
	if topLevel && element.Name == "geninfo" {
		return true
	}

	name := cleanPDMLText(element.Name)
	showname := simplifyShowname(cleanPDMLText(element.Showname))

	if strings.HasPrefix(name, "per.") {
		return true
	}

	for _, prefix := range []string{
		"Enumerated Index:",
		"Open Type Length:",
		"Sequence-Of Length:",
		"Bit String Length:",
		"Choice Index:",
		"Extension Bit:",
		"Optional Field Bit:",
		"Extension Present Bit:",
	} {
		if strings.HasPrefix(showname, prefix) {
			return true
		}
	}

	return false
}

func pdmlLabel(element pdmlElement, topLevel bool) (string, string) {
	if topLevel {
		if name := cleanPDMLText(element.Name); name != "" {
			return name, ""
		}
		return cleanPDMLText(element.Showname), ""
	}

	showname := simplifyShowname(cleanPDMLText(element.Showname))
	show := cleanPDMLText(element.Show)
	name := cleanFieldName(element.Name)

	if showname != "" {
		if left, right, ok := strings.Cut(showname, ": "); ok {
			return left, right
		}
		if show != "" && show != showname {
			return showname, show
		}
		return showname, ""
	}

	if show != "" {
		if name == "" {
			return show, ""
		}
		return name, show
	}

	if name != "" {
		return name, ""
	}

	if value := cleanPDMLText(element.Value); value != "" {
		return "value", value
	}

	return "", ""
}

func cleanFieldName(name string) string {
	name = cleanPDMLText(name)
	if name == "" {
		return ""
	}
	if idx := strings.LastIndex(name, "."); idx >= 0 && idx < len(name)-1 {
		return name[idx+1:]
	}
	return name
}

func cleanPDMLText(text string) string {
	return strings.TrimSpace(html.UnescapeString(text))
}

func isPDML(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '<'
}

func enrichProtocolLayers(layers []model.TreeNode) []model.TreeNode {
	for i := range layers {
		layers[i] = enrichTreeNode(layers[i])
	}

	priority := map[string]int{
		"frame":   0,
		"sll":     1,
		"eth":     1,
		"ip":      2,
		"ipv6":    2,
		"sctp":    3,
		"udp":     3,
		"tcp":     3,
		"pfcp":    4,
		"gtp":     4,
		"gtpv2":   4,
		"ngap":    5,
		"nas-5gs": 6,
		"diameter": 7,
	}
	sort.SliceStable(layers, func(i, j int) bool {
		pi, okI := priority[strings.ToLower(layers[i].Name)]
		pj, okJ := priority[strings.ToLower(layers[j].Name)]
		switch {
		case okI && okJ:
			return pi < pj
		case okI:
			return true
		case okJ:
			return false
		default:
			return layers[i].Name < layers[j].Name
		}
	})

	return layers
}

func enrichTreeNode(node model.TreeNode) model.TreeNode {
	for i := range node.Children {
		node.Children[i] = enrichTreeNode(node.Children[i])
	}

	switch node.Name {
	case "pLMNIdentity":
		if plmn := derivePLMN(node); plmn != "" {
			node.Value = plmn
		}
	case "5GS mobile identity":
		if value := derive5GSMobileIdentity(node); value != "" {
			node.Value = value
		}
	case "5GS registration type":
		if value := deriveRegistrationType(node); value != "" {
			node.Value = value
		}
	case "NAS key set identifier", "NAS key set identifier - ngKSI":
		if value := deriveNASKeySetIdentifier(node); value != "" {
			node.Value = value
		}
	case "UE security capability", "UE security capability - Replayed UE security capabilities":
		if value := deriveUESecurityCapability(node); value != "" {
			node.Value = value
		}
	case "s-NSSAI":
		if snssai := deriveSNSSAI(node); snssai != "" {
			node.Value = snssai
		}
	case "nR-CGI":
		if value := deriveNRCGI(node); value != "" {
			node.Value = value
		}
	case "tAI":
		if value := deriveTAI(node); value != "" {
			node.Value = value
		}
	}

	node.Children = pruneDuplicateChildren(node)

	return node
}

func derivePLMN(node model.TreeNode) string {
	mcc := extractCode(findChildValue(node, "Mobile Country Code (MCC)"))
	mnc := extractCode(findChildValue(node, "Mobile Network Code (MNC)"))
	if mcc == "" || mnc == "" {
		return ""
	}
	return mcc + "-" + mnc
}

func derive5GSMobileIdentity(node model.TreeNode) string {
	identityType := primaryDisplayValue(findChildValue(node, "Type of identity"))
	supiFormat := primaryDisplayValue(findChildValue(node, "SUPI format"))
	plmn := derivePLMN(node)
	msin := findChildValue(node, "MSIN")

	parts := make([]string, 0, 4)
	if identityType != "" {
		parts = append(parts, identityType)
	}
	if supiFormat != "" {
		parts = append(parts, supiFormat)
	}
	if plmn != "" {
		parts = append(parts, "PLMN "+plmn)
	}
	if msin != "" {
		parts = append(parts, "MSIN "+msin)
	}
	return strings.Join(parts, ", ")
}

func deriveRegistrationType(node model.TreeNode) string {
	regType := primaryDisplayValue(findChildValue(node, "5GS registration type"))
	followOn := primaryDisplayValue(findChildValue(node, "Follow-On Request bit (FOR)"))
	parts := make([]string, 0, 2)
	if regType != "" {
		parts = append(parts, regType)
	}
	if followOn != "" {
		parts = append(parts, followOn)
	}
	return strings.Join(parts, ", ")
}

func deriveNASKeySetIdentifier(node model.TreeNode) string {
	tsc := primaryDisplayValue(findChildValue(node, "Type of security context flag (TSC)"))
	keyID := primaryDisplayValue(findChildValue(node, "NAS key set identifier"))
	if keyID == "" {
		keyID = primaryDisplayValue(findChildValue(node, "ngKSI"))
	}
	parts := make([]string, 0, 2)
	if tsc != "" {
		parts = append(parts, tsc)
	}
	if keyID != "" {
		parts = append(parts, "KSI "+keyID)
	}
	return strings.Join(parts, ", ")
}

func deriveUESecurityCapability(node model.TreeNode) string {
	encryption := collectSupportedAlgorithms(node, []string{"5G-EA", "128-5G-EA", "EEA"})
	integrity := collectSupportedAlgorithms(node, []string{"5G-IA", "128-5G-IA", "EIA", "128-EIA"})

	parts := make([]string, 0, 2)
	if len(encryption) > 0 {
		parts = append(parts, "Enc "+strings.Join(encryption, "/"))
	}
	if len(integrity) > 0 {
		parts = append(parts, "Int "+strings.Join(integrity, "/"))
	}
	return strings.Join(parts, ", ")
}

func deriveSNSSAI(node model.TreeNode) string {
	sst := findChildValue(node, "sST")
	sd := findChildValue(node, "sD")
	switch {
	case sst != "" && sd != "":
		return "SST " + sst + ", SD " + strings.ReplaceAll(sd, ":", "")
	case sst != "":
		return "SST " + sst
	default:
		return ""
	}
}

func deriveNRCGI(node model.TreeNode) string {
	plmn := ""
	cellID := ""
	for _, child := range node.Children {
		if child.Name == "pLMNIdentity" {
			plmn = child.Value
		}
		if strings.Contains(strings.ToLower(child.Name), "nrcellidentity") {
			cellID = child.Value
		}
	}
	switch {
	case plmn != "" && cellID != "":
		return "PLMN " + plmn + ", Cell " + cellID
	case plmn != "":
		return "PLMN " + plmn
	default:
		return ""
	}
}

func deriveTAI(node model.TreeNode) string {
	plmn := ""
	tac := ""
	for _, child := range node.Children {
		if child.Name == "pLMNIdentity" {
			plmn = child.Value
		}
		if child.Name == "tAC" {
			tac = primaryDisplayValue(child.Value)
		}
	}
	switch {
	case plmn != "" && tac != "":
		return "PLMN " + plmn + ", TAC " + tac
	case plmn != "":
		return "PLMN " + plmn
	default:
		return ""
	}
}

func findChildValue(node model.TreeNode, childName string) string {
	for _, child := range node.Children {
		if child.Name == childName {
			return child.Value
		}
	}
	return ""
}

func collectSupportedAlgorithms(node model.TreeNode, prefixes []string) []string {
	values := make([]string, 0)
	for _, child := range node.Children {
		value := strings.ToLower(child.Value)
		if strings.Contains(value, "not supported") || !strings.Contains(value, "supported") {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(child.Name, prefix) {
				values = append(values, child.Name)
				break
			}
		}
	}
	return values
}

func pruneDuplicateChildren(node model.TreeNode) []model.TreeNode {
	if node.Value == "" || len(node.Children) == 0 {
		return node.Children
	}
	children := make([]model.TreeNode, 0, len(node.Children))
	for _, child := range node.Children {
		if child.Name == node.Name {
			continue
		}
		children = append(children, child)
	}
	return children
}

func extractCode(value string) string {
	if value == "" {
		return ""
	}
	start := strings.LastIndex(value, "(")
	end := strings.LastIndex(value, ")")
	if start >= 0 && end > start+1 {
		return value[start+1 : end]
	}
	return value
}

func primaryDisplayValue(value string) string {
	if value == "" {
		return ""
	}
	if head, _, ok := strings.Cut(value, " ("); ok {
		return head
	}
	return value
}

func simplifyShowname(showname string) string {
	if showname == "" {
		return ""
	}
	if left, right, ok := strings.Cut(showname, " = "); ok && looksLikeBitPrefix(left) {
		return strings.TrimSpace(right)
	}
	return showname
}

func looksLikeBitPrefix(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r == ' ' || r == '.' || r == '0' || r == '1':
		default:
			return false
		}
	}
	return true
}

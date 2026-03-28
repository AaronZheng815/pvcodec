package tshark

import (
	"testing"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

func TestJsonMapToTree(t *testing.T) {
	input := map[string]any{
		"frame": map[string]any{
			"frame.number": "1",
			"frame.len":    "100",
		},
		"ip": map[string]any{
			"ip.src": "10.0.0.1",
			"ip.dst": "10.0.0.2",
		},
	}

	nodes := jsonMapToTree(input)
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	names := map[string]bool{}
	for _, n := range nodes {
		names[n.Name] = true
	}
	if !names["frame"] || !names["ip"] {
		t.Errorf("expected frame and ip nodes, got %v", names)
	}
}

func TestJsonMapToTreeFiltersRaw(t *testing.T) {
	input := map[string]any{
		"eth":     map[string]any{"eth.src": "00:11:22:33:44:55"},
		"eth_raw": []any{"001122334455"},
	}

	nodes := jsonMapToTree(input)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (raw filtered), got %d", len(nodes))
	}
	if nodes[0].Name != "eth" {
		t.Errorf("expected eth, got %s", nodes[0].Name)
	}
}

func TestJsonValueToNodeNested(t *testing.T) {
	input := map[string]any{
		"ngap": map[string]any{
			"ngap.procedureCode": "15",
			"ngap.initiatingMessage": map[string]any{
				"ngap.value": "InitialUEMessage",
			},
		},
	}

	nodes := jsonMapToTree(input)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 top-level node, got %d", len(nodes))
	}

	ngap := nodes[0]
	if ngap.Name != "ngap" {
		t.Fatalf("expected ngap, got %s", ngap.Name)
	}
	if len(ngap.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(ngap.Children))
	}
}

func TestJsonValueToNodeSingleElementArray(t *testing.T) {
	node := jsonValueToNode("test", []any{"single_value"})
	if node.Value != "single_value" {
		t.Errorf("single-element array should unwrap, got value=%q children=%d",
			node.Value, len(node.Children))
	}
}

func TestParsePDMLDetail(t *testing.T) {
	input := []byte(`<?xml version="1.0"?>
<pdml>
  <packet>
    <proto name="geninfo" showname="General information">
      <field name="num" showname="Number" show="7"/>
    </proto>
    <proto name="ngap" showname="NG Application Protocol">
      <field name="ngap.pLMNIdentity" showname="pLMNIdentity: 64f000" show="64:f0:00">
        <field name="e212.mcc" showname="Mobile Country Code (MCC): China (460)" show="460"/>
        <field name="e212.mnc" showname="Mobile Network Code (MNC): China Mobile (00)" show="00"/>
      </field>
    </proto>
  </packet>
</pdml>`)

	detail, err := parsePDMLDetail(input, 7)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Index != 7 {
		t.Fatalf("expected frame 7, got %d", detail.Index)
	}
	if len(detail.Layers) != 1 {
		t.Fatalf("expected 1 visible top-level layer, got %d", len(detail.Layers))
	}
	if detail.Layers[0].Name != "ngap" {
		t.Fatalf("expected ngap top-level layer, got %s", detail.Layers[0].Name)
	}
	child := detail.Layers[0].Children[0]
	if child.Name != "pLMNIdentity" || child.Value != "460-00" {
		t.Fatalf("unexpected PDML field mapping: %+v", child)
	}
	if len(child.Children) < 2 {
		t.Fatalf("expected MCC/MNC children, got %+v", child.Children)
	}
	if child.Children[0].Name != "Mobile Country Code (MCC)" || child.Children[0].Value != "China (460)" {
		t.Fatalf("unexpected MCC node: %+v", child.Children[0])
	}
}

func TestParsePDMLDetailSkipsPERNoise(t *testing.T) {
	input := []byte(`<?xml version="1.0"?>
<pdml>
  <packet>
    <proto name="ngap" showname="NG Application Protocol">
      <field name="per.choice_index" showname="Choice Index: 1" show="1"/>
      <field name="ngap.pLMNIdentity" showname="pLMNIdentity: 64f000" show="64:f0:00">
        <field name="per.enum_index" showname="Enumerated Index: 0" show="0"/>
        <field name="e212.mcc" showname="Mobile Country Code (MCC): China (460)" show="460"/>
      </field>
    </proto>
  </packet>
</pdml>`)

	detail, err := parsePDMLDetail(input, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Layers) != 1 {
		t.Fatalf("expected 1 top-level layer, got %d", len(detail.Layers))
	}
	if len(detail.Layers[0].Children) != 1 {
		t.Fatalf("expected only semantic child nodes, got %+v", detail.Layers[0].Children)
	}
	if detail.Layers[0].Children[0].Name != "pLMNIdentity" {
		t.Fatalf("unexpected surviving child: %+v", detail.Layers[0].Children[0])
	}
	if len(detail.Layers[0].Children[0].Children) != 1 {
		t.Fatalf("expected only MCC child, got %+v", detail.Layers[0].Children[0].Children)
	}
}

func TestParsePDMLDetailBuildsSemanticNGAPValues(t *testing.T) {
	input := []byte(`<?xml version="1.0"?>
<pdml>
  <packet>
    <proto name="frame" showname="Frame 18"/>
    <proto name="ngap" showname="NG Application Protocol">
      <field name="ngap.nR_CGI_element" showname="nR-CGI">
        <field name="ngap.pLMNIdentity" showname="pLMNIdentity: 64f000" show="64:f0:00">
          <field name="e212.mcc" showname="Mobile Country Code (MCC): China (460)" show="460"/>
          <field name="e212.mnc" showname="Mobile Network Code (MNC): China Mobile (00)" show="00"/>
        </field>
        <field name="ngap.NRCellIdentity" showname="0000 .... = nRCellIdentity: 0x000018006" show="0x000018006"/>
      </field>
      <field name="ngap.tAI_element" showname="tAI">
        <field name="ngap.pLMNIdentity" showname="pLMNIdentity: 64f000" show="64:f0:00">
          <field name="e212.mcc" showname="Mobile Country Code (MCC): China (460)" show="460"/>
          <field name="e212.mnc" showname="Mobile Network Code (MNC): China Mobile (00)" show="00"/>
        </field>
        <field name="ngap.tAC" showname="tAC: 1 (0x000001)" show="1"/>
      </field>
      <field name="ngap.s_NSSAI_element" showname="s-NSSAI">
        <field name="ngap.sST" showname="sST: 01" show="01"/>
        <field name="ngap.sD" showname="sD: 00:00:01" show="00:00:01"/>
      </field>
    </proto>
    <proto name="ip" showname="Internet Protocol Version 4"/>
  </packet>
</pdml>`)

	detail, err := parsePDMLDetail(input, 18)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Layers) < 2 {
		t.Fatalf("expected multiple layers, got %+v", detail.Layers)
	}

	foundNGAP := false
	var ngapChildren []model.TreeNode
	for _, layer := range detail.Layers {
		if layer.Name == "ngap" {
			ngapChildren = layer.Children
			foundNGAP = true
			break
		}
	}
	if !foundNGAP {
		t.Fatalf("expected NGAP layer, got %+v", detail.Layers)
	}

	values := map[string]string{}
	for _, child := range ngapChildren {
		values[child.Name] = child.Value
	}
	if values["nR-CGI"] != "PLMN 460-00, Cell 0x000018006" {
		t.Fatalf("unexpected nR-CGI value: %q", values["nR-CGI"])
	}
	if values["tAI"] != "PLMN 460-00, TAC 1" {
		t.Fatalf("unexpected tAI value: %q", values["tAI"])
	}
	if values["s-NSSAI"] != "SST 01, SD 000001" {
		t.Fatalf("unexpected s-NSSAI value: %q", values["s-NSSAI"])
	}
}

func TestParsePDMLDetailBuildsSemanticNASValues(t *testing.T) {
	input := []byte(`<?xml version="1.0"?>
<pdml>
  <packet>
    <proto name="nas-5gs" showname="Non-Access-Stratum 5GS (NAS)PDU">
      <field name="" show="5GS registration type">
        <field name="nas-5gs.mm.for" showname=".... 1... = Follow-On Request bit (FOR): Follow-on request pending" show="True"/>
        <field name="nas-5gs.mm.5gs_reg_type" showname=".... .001 = 5GS registration type: initial registration (1)" show="1"/>
      </field>
      <field name="" show="NAS key set identifier">
        <field name="nas-5gs.mm.tsc.h1" showname="0... .... = Type of security context flag (TSC): Native security context (for KSIAMF)" show="False"/>
        <field name="nas-5gs.mm.nas_key_set_id.h1" showname=".111 .... = NAS key set identifier: 7" show="7"/>
      </field>
      <field name="" show="5GS mobile identity">
        <field name="nas-5gs.mm.suci.supi_fmt" showname=".000 .... = SUPI format: IMSI (0)" show="0"/>
        <field name="nas-5gs.mm.type_id" showname=".... .001 = Type of identity: SUCI (1)" show="1"/>
        <field name="e212.mcc" showname="Mobile Country Code (MCC): China (460)" show="460"/>
        <field name="e212.mnc" showname="Mobile Network Code (MNC): China Mobile (00)" show="00"/>
        <field name="nas-5gs.mm.suci.msin" showname="MSIN: 1234560001" show="1234560001"/>
      </field>
      <field name="" show="UE security capability">
        <field name="nas-5gs.mm.5g_ea0" showname="1... .... = 5G-EA0: Supported" show="True"/>
        <field name="nas-5gs.mm.128_5g_ea1" showname=".1.. .... = 128-5G-EA1: Supported" show="True"/>
        <field name="nas-5gs.mm.5g_ia6" showname=".... ..0. = 5G-IA6: Not supported" show="False"/>
        <field name="nas-5gs.mm.128eia1" showname=".1.. .... = 128-EIA1: Supported" show="True"/>
      </field>
    </proto>
  </packet>
</pdml>`)

	detail, err := parsePDMLDetail(input, 18)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %+v", detail.Layers)
	}
	values := map[string]string{}
	for _, child := range detail.Layers[0].Children {
		values[child.Name] = child.Value
	}
	if values["5GS registration type"] != "initial registration, Follow-on request pending" {
		t.Fatalf("unexpected registration type: %q", values["5GS registration type"])
	}
	if values["NAS key set identifier"] != "Native security context, KSI 7" {
		t.Fatalf("unexpected KSI summary: %q", values["NAS key set identifier"])
	}
	if values["5GS mobile identity"] != "SUCI, IMSI, PLMN 460-00, MSIN 1234560001" {
		t.Fatalf("unexpected mobile identity summary: %q", values["5GS mobile identity"])
	}
	if values["UE security capability"] != "Enc 5G-EA0/128-5G-EA1, Int 128-EIA1" {
		t.Fatalf("unexpected security capability summary: %q", values["UE security capability"])
	}
	for _, child := range detail.Layers[0].Children {
		for _, grandChild := range child.Children {
			if grandChild.Name == child.Name {
				t.Fatalf("expected duplicate child %q to be pruned: %+v", child.Name, child)
			}
		}
	}
}

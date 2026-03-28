package tshark

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

var protocolFilters = map[string]string{
	"NGAP":     "ngap",
	"NAS":      "nas-5gs",
	"Diameter": "diameter",
	"GTP":      "gtp || gtpv2",
}

type Runner interface {
	Output(name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Output(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

type TShark struct {
	path   string
	runner Runner
}

func New() *TShark {
	return NewWithRunner(execRunner{})
}

func NewWithRunner(runner Runner) *TShark {
	path := discoverTSharkPath()
	if path == "" {
		return &TShark{runner: runner}
	}
	return &TShark{path: path, runner: runner}
}

func NewForTest(runner Runner) *TShark {
	return &TShark{path: "tshark", runner: runner}
}

func discoverTSharkPath() string {
	if configured := strings.TrimSpace(os.Getenv("PVCODEC_TSHARK_PATH")); configured != "" {
		if fileExists(configured) {
			return configured
		}
	}

	if path, err := exec.LookPath("tshark"); err == nil {
		return path
	}

	for _, candidate := range []string{
		"/Applications/Wireshark.app/Contents/MacOS/tshark",
		"/opt/homebrew/bin/tshark",
		"/usr/local/bin/tshark",
	} {
		if fileExists(candidate) {
			return candidate
		}
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (t *TShark) Available() bool {
	return t != nil && t.path != ""
}

func (t *TShark) Version() string {
	if !t.Available() {
		return ""
	}
	out, err := t.runner.Output(t.path, "--version")
	if err != nil {
		return ""
	}
	first, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(first)
}

func (t *TShark) ListPackets(filePath string, protocol string) ([]model.PacketSummary, error) {
	if !t.Available() {
		return nil, fmt.Errorf("tshark is not installed; please install Wireshark/tshark to use this tool")
	}

	args := []string{
		"-r", filePath,
		"-T", "fields",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ipv6.src",
		"-e", "ip.dst",
		"-e", "ipv6.dst",
		"-e", "_ws.col.Protocol",
		"-e", "frame.len",
		"-e", "_ws.col.Info",
		"-E", "header=n",
		"-E", "separator=/t",
		"-E", "quote=n",
	}

	if filter := DisplayFilter(protocol); filter != "" {
		args = append(args, "-Y", filter)
	}

	output, err := t.runner.Output(t.path, args...)
	packets, parseErr := parseSummaryOutput(output)
	if parseErr != nil {
		return nil, parseErr
	}
	if err != nil {
		if isIgnorableTSharkWarning(err) {
			return packets, nil
		}
		return nil, formatCommandError("tshark summary", err)
	}
	return packets, nil
}

func parseSummaryOutput(data []byte) ([]model.PacketSummary, error) {
	packets := make([]model.PacketSummary, 0)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 9 {
			continue
		}

		index, _ := strconv.Atoi(fields[0])
		length, _ := strconv.Atoi(fields[7])

		srcAddr := fields[2]
		if srcAddr == "" {
			srcAddr = fields[3]
		}
		dstAddr := fields[4]
		if dstAddr == "" {
			dstAddr = fields[5]
		}

		packets = append(packets, model.PacketSummary{
			Index:    index,
			SrcAddr:  srcAddr,
			DstAddr:  dstAddr,
			Protocol: fields[6],
			Length:   length,
			Info:     fields[8],
		})
	}
	return packets, scanner.Err()
}

func (t *TShark) PacketDetail(filePath string, frameNumber int) (model.PacketDetail, error) {
	if !t.Available() {
		return model.PacketDetail{}, fmt.Errorf("tshark is not installed")
	}

	args := []string{
		"-r", filePath,
		"-Y", fmt.Sprintf("frame.number == %d", frameNumber),
		"-T", "pdml",
	}

	output, err := t.runner.Output(t.path, args...)
	detail, parseErr := parseDetailOutput(output, frameNumber)
	if parseErr != nil {
		return model.PacketDetail{}, parseErr
	}
	if err != nil {
		if isIgnorableTSharkWarning(err) {
			return detail, nil
		}
		return model.PacketDetail{}, formatCommandError("tshark detail", err)
	}
	return detail, nil
}

func parseDetailOutput(data []byte, frameNumber int) (model.PacketDetail, error) {
	if isPDML(data) {
		return parsePDMLDetail(data, frameNumber)
	}

	var frames []map[string]any
	if err := json.Unmarshal(data, &frames); err != nil {
		return model.PacketDetail{}, err
	}
	if len(frames) == 0 {
		return model.PacketDetail{}, fmt.Errorf("no frame found for number %d", frameNumber)
	}

	frame := frames[0]
	source, _ := frame["_source"].(map[string]any)
	if source == nil {
		return model.PacketDetail{}, fmt.Errorf("unexpected tshark output structure")
	}

	layersRaw, _ := source["layers"].(map[string]any)
	layers := jsonMapToTree(layersRaw)

	return model.PacketDetail{
		Index:  frameNumber,
		Layers: layers,
	}, nil
}

func DisplayFilter(protocol string) string {
	if protocol == "" || protocol == "All" {
		return ""
	}
	if f, ok := protocolFilters[protocol]; ok {
		return f
	}
	return strings.ToLower(protocol)
}

func formatCommandError(stage string, err error) error {
	message := strings.TrimSpace(tsharkErrorOutput(err))
	if message == "" {
		return fmt.Errorf("%s failed: %w", stage, err)
	}
	return fmt.Errorf("%s failed: %s", stage, message)
}

func isIgnorableTSharkWarning(err error) bool {
	message := strings.ToLower(tsharkErrorOutput(err))
	return strings.Contains(message, "appears to have been cut short in the middle of a packet")
}

func tsharkErrorOutput(err error) string {
	if err == nil {
		return ""
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(exitErr.Stderr)
	}
	return err.Error()
}

package decode

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/AaronZheng815/pvcodec/internal/model"
)

type TSharkFallback struct {
	path string
}

func NewTSharkFallback() *TSharkFallback {
	path, err := exec.LookPath("tshark")
	if err != nil {
		return &TSharkFallback{}
	}
	return &TSharkFallback{path: path}
}

func (t *TSharkFallback) Available() bool {
	return t != nil && t.path != ""
}

func (t *TSharkFallback) DecodePacket(captureFile string, frameNumber int) (Result, error) {
	if !t.Available() {
		return Result{}, fmt.Errorf("tshark is not installed")
	}

	cmd := exec.Command(t.path,
		"-r", captureFile,
		"-Y", fmt.Sprintf("frame.number == %d", frameNumber),
		"-T", "json",
		"--no-duplicate-keys",
	)

	output, err := cmd.Output()
	if err != nil {
		return Result{}, err
	}

	var decoded any
	if err := json.Unmarshal(output, &decoded); err != nil {
		return Result{}, err
	}

	return Result{
		Info:     "tshark fallback",
		Nodes:    []model.TreeNode{BuildTree("tshark", decoded)},
		Fallback: true,
	}, nil
}

package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type RawPacket struct {
	Index          int
	Timestamp      time.Time
	Data           []byte
	CaptureLength  int
	OriginalLength int
	LinkType       layers.LinkType
}

func ReadFile(path string) ([]RawPacket, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	magic := binary.BigEndian.Uint32(header)
	switch magic {
	case 0x0A0D0D0A:
		return readPCAPNG(file)
	default:
		return readPCAP(file)
	}
}

func readPCAP(r io.Reader) ([]RawPacket, error) {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, err
	}

	linkType := reader.LinkType()
	var packets []RawPacket
	for i := 1; ; i++ {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			return packets, nil
		}
		if err != nil {
			return nil, err
		}

		packets = append(packets, RawPacket{
			Index:          i,
			Timestamp:      ci.Timestamp,
			Data:           append([]byte(nil), data...),
			CaptureLength:  ci.CaptureLength,
			OriginalLength: ci.Length,
			LinkType:       linkType,
		})
	}
}

func readPCAPNG(r io.Reader) ([]RawPacket, error) {
	reader, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, err
	}

	linkType := reader.LinkType()
	var packets []RawPacket
	for i := 1; ; i++ {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			return packets, nil
		}
		if err != nil {
			return nil, err
		}

		packets = append(packets, RawPacket{
			Index:          i,
			Timestamp:      ci.Timestamp,
			Data:           bytes.Clone(data),
			CaptureLength:  ci.CaptureLength,
			OriginalLength: ci.Length,
			LinkType:       linkType,
		})
	}
}

func ValidateFileName(name string) error {
	if name == "" {
		return fmt.Errorf("missing filename")
	}
	return nil
}

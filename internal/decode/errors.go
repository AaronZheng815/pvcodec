package decode

import "fmt"

type ErrDecoderNotFound struct {
	Protocol any
}

func (e ErrDecoderNotFound) Error() string {
	return fmt.Sprintf("decoder not found for protocol %v", e.Protocol)
}

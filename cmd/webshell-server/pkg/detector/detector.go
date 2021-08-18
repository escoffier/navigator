package detector

import (
	"io"
)

type Detector interface {
	Detect(b []byte) (int, error)
	DetectFromReader(reader io.Reader) (int, error)
}

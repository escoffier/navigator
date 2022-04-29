package detector

import (
	"context"
	"io"
)

type Detector interface {
	Detect(ctx context.Context, b []byte) (int, error)
	DetectFromReader(ctx context.Context, reader io.Reader) (int, error)
}

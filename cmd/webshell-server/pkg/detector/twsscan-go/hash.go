package twsscan_go

import (
	"crypto/sha1"
	"errors"
	"fmt"
)

var UnknownHashScanError = errors.New("un known hash scan")

type hashScanResult struct {
	filename string
}

func (h *hashScanResult) FileName() string { return h.filename }

func (h *hashScanResult) Score() float64 { return 1 }

func (h *hashScanResult) Type() ScanType { return HashScanType }

func Hash(content []byte) (*hashScanResult, error) {
	h := sha1.New()
	h.Write(content)
	v := fmt.Sprintf("%x", h.Sum(nil))
	if filename, ok := DefaultHashDataMap[v]; ok {
		return &hashScanResult{filename: filename}, nil
	}

	return nil, UnknownHashScanError
}

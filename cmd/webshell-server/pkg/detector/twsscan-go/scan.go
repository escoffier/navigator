package twsscan_go

import "errors"

var NoResultError = errors.New("no scan result")

func Scan(content []byte) (Result, error) {
	h, err := Hash(content)
	if err == nil {
		return h, nil
	}

	s, err := Fuzz(content)
	if err == nil {
		return s, nil

	}

	return nil, NoResultError
}

type ScanType uint8

const (
	HashScanType = iota + 1
	FuzzScanType
)

func (s ScanType) String() string {
	switch s {
	case HashScanType:
		return "hash"
	case FuzzScanType:
		return "fuzz"
	default:
		return ""
	}
}

type Result interface {
	FileName() string
	Score() float64
	Type() ScanType
}

package twsscan_go

import (
	"errors"
	"sort"
)

var UnknownFuzzScanError = errors.New("unknown fuzz scan")

type fuzzScanResult struct {
	filename string
	score    float64
}

func (f *fuzzScanResult) FileName() string { return f.filename }

func (f *fuzzScanResult) Score() float64 { return f.score }

func (f *fuzzScanResult) Type() ScanType { return FuzzScanType }

func Fuzz(content []byte) (*fuzzScanResult, error) {
	content = ExtractFile(content)
	var d = make([]*fuzzScanResult, 0)
	for _, v := range DefaultFuzzData {
		if score := distance(BytesToString(content), v.content); score >= 0.5 {
			d = append(d, &fuzzScanResult{filename: v.fileName, score: score})
		}
	}

	if len(d) == 0 {
		return nil, UnknownFuzzScanError
	}

	// sort by score
	sort.Slice(d, func(i, j int) bool {
		return d[i].score > d[j].score
	})

	return d[0], nil
}

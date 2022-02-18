package detector

import (
	"io"
	"io/ioutil"

	"github.com/pkg/errors"

	twsscan "gitlab.com/piccolo_su/vegeta/cmd/webshell-server/pkg/detector/twsscan"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type simpleScanDetector struct{}

func NewSimpleScanDetector() Detector {
	return &simpleScanDetector{}
}

func (s *simpleScanDetector) Detect(b []byte) (int, error) {
	logging.GetLogger().Debug().Msg("regex detection start")

	r, err := twsscan.Scan(b)
	if err != nil {
		return 0, err
	}

	score := s.score(r)

	logging.GetLogger().Debug().Msgf("regex detection end. score: %d", score)

	return score, nil
}

func (s *simpleScanDetector) DetectFromReader(reader io.Reader) (int, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return 0, errors.Wrap(err, "read data failed from a reader")
	}

	return s.Detect(b)
}

// rules: https://tensorsecurity.feishu.cn/docs/doccn20nmfoa4z9oKLpkRbnId6c
func (s *simpleScanDetector) score(r twsscan.Result) int {
	if r.Type() == twsscan.HashScanType {
		return 10
	}

	if s := r.Score(); s > 0.85 {
		return 9
	} else if s > 0.65 && s <= 0.85 {
		return 2
	} else if s > 0.5 && s <= 0.65 {
		return 1
	} else {
		return 0
	}
}

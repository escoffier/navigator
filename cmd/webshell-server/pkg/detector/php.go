package detector

import (
	"io"
	"io/ioutil"
	"sync"

	"github.com/pkg/errors"
	phpruntime "scm.tensorsecurity.cn/tensorsecurity-rd/cloudwalker/tool/webshell-detector/php"
	phpdetector "scm.tensorsecurity.cn/tensorsecurity-rd/cloudwalker/tool/webshell-detector/src"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	defaultPHPDetector *phpDetector
	once               sync.Once
)

type phpDetector struct {
	*phpdetector.Detector
	mu sync.Mutex //
}

// NewPHPDetector is the singleton constructor of phpDetector.
func NewPHPDetector() Detector {
	once.Do(func() {
		err := phpruntime.Start()
		if err != nil {
			logging.GetLogger().Fatal().Err(err).Msg("star php phpDetector failed")
		}

		d, err := phpdetector.NewDefaultDetector(phpruntime.Stdin, phpruntime.Stdout)
		if err != nil {
			logging.GetLogger().Fatal().Err(err).Msg("get php phpDetector failed")
		}

		defaultPHPDetector = &phpDetector{Detector: d}
	})

	return defaultPHPDetector
}

// DetectFromReader detects the content from a reader.
func (d *phpDetector) DetectFromReader(reader io.Reader) (int, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return 0, errors.Wrap(err, "read data failed from a reader")
	}

	return d.Detect(b)
}

// Detect detects the content.
func (d *phpDetector) Detect(b []byte) (int, error) {
	logging.GetLogger().Debug().Msg("php detection start")

	d.mu.Lock()
	defer d.mu.Unlock()

	score, err := d.Predict(b)
	if err != nil {
		return 0, errors.Wrap(err, "detect failed")
	}

	logging.GetLogger().Debug().Msgf("php detection, end. score: %d", score)
	return d.risk(score), nil
}

// https://tensorsecurity.feishu.cn/docs/doccn20nmfoa4z9oKLpkRbnId6c
func (d *phpDetector) risk(score int) int {
	var risk int
	switch score {
	case 1, 2:
		risk = 4
	case 3:
		risk = 5
	case 4:
		risk = 6
	case 5:
		risk = 8
	case 6, 7:
		risk = 9
	default:
		risk = 0
	}

	return risk
}

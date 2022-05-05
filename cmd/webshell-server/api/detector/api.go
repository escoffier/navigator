package detector

import (
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/pkg/detector"
	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/pkg/re"
	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/tools"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// 牧云开启的开关，默认开启
var closeCloudWalker = false

func init() {
	closeCloudWalker = os.Getenv("CLOSE_CLOUD_WALKER") == "1"
	if closeCloudWalker {
		logging.GetLogger().Warn().Msgf(
			"environment variable `CLOSE_CLOUD_WALKER` has been set, value is `%s`",
			os.Getenv("CLOSE_CLOUD_WALKER"),
		)
		logging.GetLogger().Warn().Msg("cloudwalker detector has been closed")
	}
}

type Server struct {
	phpDetector        detector.Detector
	simpleScanDetector detector.Detector
	re                 re.Regexes
}

func NewAPIServer() *Server {
	return &Server{
		phpDetector:        detector.NewPHPDetector(),
		simpleScanDetector: detector.NewSimpleScanDetector(),
		re:                 re.SimpleRegex,
	}
}

// File detects webshell
// rules: https://tensorsecurity.feishu.cn/docs/doccn20nmfoa4z9oKLpkRbnId6c
func (s *Server) File(ctx *gin.Context) {

	body, err := ioutil.ReadAll(ctx.Request.Body)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusBadRequest, errors.Wrap(err, "read data failed from a reader"))
		return
	}

	score, err := s.simpleScanDetector.Detect(ctx.Request.Context(), body)
	if err == nil && score < 9 {
		var phpScore int

		if !closeCloudWalker {
			phpScore, err = s.phpDetector.Detect(ctx.Request.Context(), body)
			if err != nil {
				logging.GetLogger().Info().Msgf("webshell detection failed, err: %v", err)
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}
		}

		score += phpScore
	}

	if score > 10 {
		score = 10
	}

	res := &FileResp{
		Score: score,
	}

	// 当分数不为0时，需要扫描出代码片段
	if score != 0 {
		res.Codes = tools.Byte2Strings(s.re.Scan(body))
	}

	ctx.JSON(http.StatusOK, res)
}

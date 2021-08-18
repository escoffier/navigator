package detector

import (
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/pkg/detector"
	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/pkg/re"
	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/tools"
)

type Server struct {
	phpDetector        detector.Detector
	simpleScanDetector detector.Detector
	re                 re.Regexes
}

func NewApiServer() *Server {
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

	score, err := s.simpleScanDetector.Detect(body)
	if err == nil && score < 9 {
		phpScore, err := s.phpDetector.Detect(body)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
			return
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

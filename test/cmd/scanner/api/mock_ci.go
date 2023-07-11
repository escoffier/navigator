package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type MockCiApiSrv struct {
	policy scanner_ci.Policy
}

func NewMockCiApiSrv() *MockCiApiSrv {
	return &MockCiApiSrv{}
}

func (c *MockCiApiSrv) SetPolicy(policy scanner_ci.Policy) {
	c.policy = policy
}

// GetCiPolicy used for ci-tool requesting policy
func (c *MockCiApiSrv) GetCiPolicy(ctx *gin.Context) {

	logging.Get().Info().Msg("get policy ok")
	ctx.JSON(http.StatusOK, c.policy)
}

func (c *MockCiApiSrv) MatchVulnerability(ctx *gin.Context) {
	logging.Get().Debug().Msg("recv vuln analyze request")

	imageArtifact := scanner_ci.ImageArtifact{}
	err := ctx.BindJSON(&imageArtifact)
	if err != nil {
		logging.Get().Err(err).Msg("bad request format")
		response.JSONError(ctx, fmt.Errorf("bad request format"))
		return
	}

	ciCtl, err := ci.NewCiController(nil)
	if err != nil {
		logging.Get().Err(err).Msg("create ci controller failed")
		response.JSONError(ctx, fmt.Errorf("create ci controller failed"))
		return
	}

	logging.Get().Debug().Msg("start match")
	res, err := ciCtl.VulnerabilityMatch(imageArtifact)
	if err != nil {
		logging.Get().Err(err).Msg("analyze vuln failed")
		response.JSONError(ctx, fmt.Errorf("analyze failed"))
		return
	}
	logging.Get().Debug().Msg("match vuln end")

	rsp := &scanner_ci.ImageVulnerabilities{
		ImageName: imageArtifact.ImageName,
		UUID:      imageArtifact.UUID,
		Results:   res,
	}
	ctx.JSON(http.StatusOK, rsp)
}

func (c *MockCiApiSrv) SaveResult(ctx *gin.Context) {
	result := scanner_ci.PolicyResult{}
	err := ctx.BindJSON(&result)
	if err != nil {
		logging.Get().Err(err).Msg("bad request")
		response.JSONError(ctx, fmt.Errorf("bad request"))
		return
	}
	req := ctx.Request
	req.Header.Get("token")
	// logging.Get().Trace().Interface("result", result).Msg("get ci result")

	ctx.JSON(http.StatusOK, nil)
}

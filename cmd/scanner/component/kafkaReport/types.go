package imagesecReport

import (
	"context"

	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageDetectTaskService interface {
	CreateImageDetectTask(ctx context.Context,
		imageSearchParam imagesecModel.ImageSearchApiParam,
		taskInfo imagesecModel.ImageDetectTask,
		policy *imagesecModel.SecurityPolicy,
	) error
}

type ReceiveMQReportService interface {
	ReceiveReport(ctx context.Context) error
}

type VulnMatcher interface {
	MatchVuln(ctx context.Context, artifactDetail ftypes.ArtifactDetail) (report.Results, error)
	AddDetailVuln(ctx context.Context, vuln *imagesecModel.Vuln) *imagesecModel.Vuln
}

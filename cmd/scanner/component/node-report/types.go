package nodereport

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageDetectTaskService interface {
	CreateImageDetectTask(ctx context.Context,
		imageSearchParam imagesecModel.ImageListParam,
		policySearchParam imagesecModel.SearchSecurityPolicyParam,
		taskInfo imagesecModel.ImageDetectTask,
	) error
}

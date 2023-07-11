package nodereport

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageDetectTaskService interface {
	CreateImageDetectTask(ctx context.Context,
		imageSearchParam imagesecModel.ImageListParam,
		taskInfo imagesecModel.ImageDetectTask,
	) error
}

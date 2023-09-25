package imagesecReport

import (
	"context"

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

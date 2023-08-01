package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func CheckImageHasErr(ctx context.Context, data imagesecModel.ImageDataForDeployRes,
	policy *imagesecModel.SecurityPolicy) bool {
	if policy == nil || !policy.Enable {
		return false
	}
	return len(data.Errs) > 0
}

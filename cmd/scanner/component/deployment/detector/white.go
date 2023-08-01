package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func CheckImageWhite(ctx context.Context, data imagesecModel.ImageDataForDeployRes,
	policy *imagesecModel.SecurityPolicy) bool {

	if policy == nil || !policy.Enable {
		return true
	}

	if !data.Scanned && policy.DeployMod == imagesecModel.DeployModSafe {
		return false
	}
	return true
}

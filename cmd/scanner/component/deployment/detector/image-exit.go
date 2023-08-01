package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func CheckImageExit(ctx context.Context, data imagesecModel.ImageDataForDeployRes,
	policy *imagesecModel.SecurityPolicy) bool {

	if policy == nil || !policy.Enable {
		return true
	}
	if !data.Exit && policy.DeployMod == imagesecModel.DeployModSafe {
		return false
	}
	return true
}

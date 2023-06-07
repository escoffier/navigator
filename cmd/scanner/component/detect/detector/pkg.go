package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImagePkg(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if !policy.Pkg.Enable {
		return ans
	}
	black := policy.Pkg.Black

	for i := range data.Pkg {
		for j := range black {
			if data.Pkg[i].Name == black[j].Name && data.Pkg[i].Version == black[j].InstallVersion {
				ans = append(ans, &imagesecModel.ImageDetectResult{
					DetectType:    imagesecModel.DetectTypePkgVersionRule,
					Flag:          util.SetBit1(util.SetBit1(0, imagesecModel.FlagDetectInBlack), imagesecModel.FlagDetectException),
					UniqueTarget:  data.Pkg[i].UniqueID,
					ImageUniqueID: data.Image.UniqueID,
					PolicyID:      policy.ID,
				})
			}
		}
	}
	return ans
}

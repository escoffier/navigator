package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageLicense(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if !policy.License.Enable {
		return ans
	}
	black := policy.License.Black

	for i := range data.Pkg {
		licenses := data.Pkg[i].License
		for j := range black {
			for k := range licenses {
				if licenses[k] == black[j] {
					ans = append(ans, &imagesecModel.ImageDetectResult{
						DetectType: imagesecModel.DetectTypePkgLicenseRule,
						Flag: util.SetBit1(util.SetBit1(0, imagesecModel.FlagDetectInBlack),
							imagesecModel.FlagDetectException),
						UniqueTarget:  data.Pkg[i].UniqueID,
						ImageUniqueID: data.Image.UniqueID,
						PolicyID:      policy.ID,
					})
				}
			}
		}
	}
	return ans
}

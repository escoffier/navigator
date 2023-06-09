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
		var flag uint64

		for j := range black {
			for k := range licenses {
				if licenses[k] == black[j] {
					flag = util.SetBit1(util.SetBit1(flag, imagesecModel.FlagDetectInBlack),
						imagesecModel.FlagDetectException)
				}
			}
		}

		if flag > 0 {
			ans = append(ans, &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypePkgLicenseRule,
				Flag:          flag,
				UniqueTarget:  data.Pkg[i].UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			})
		}
	}
	return ans
}

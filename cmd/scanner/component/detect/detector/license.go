package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageLicense(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.License.Enable || len(data.License) == 0 {
		return ans
	}
	black := policy.License.Black

	for i := range data.License {
		var flag uint64
		for j := range black {
			if data.License[i].Name == black[j] {
				flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
			}
		}

		if util.ExistBit1(flag, imagesecModel.FlagDetectException) && !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) {
			switch policy.License.Action {
			case imagesecModel.DeployActionBlock:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
			case imagesecModel.DeployActionAlarm:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
			}
		}
		if flag > 0 {
			red := &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeLicenseRule,
				Flag:          flag,
				UniqueTarget:  data.License[i].UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			}

			ans = append(ans, red)
		}
	}
	return ans
}

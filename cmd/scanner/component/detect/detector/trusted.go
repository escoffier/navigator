package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckTrustedImage(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.TrustImage.Enable {
		return ans
	}
	if len(data.TrustedImage) == 0 || !data.TrustedImage[0].Trusted {
		var flag uint64
		flag = util.SetBit1(flag, imagesecModel.FlagDetectException)

		switch policy.TrustImage.Action {
		case imagesecModel.DeployActionBlock:
			flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
		case imagesecModel.DeployActionAlarm:
			flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
		}

		red := &imagesecModel.ImageDetectResult{
			DetectType:    imagesecModel.DetectTypeTrustedImageRule,
			Flag:          flag,
			ImageUniqueID: data.Image.UniqueID,
			UniqueTarget:  data.Image.UniqueID,
			PolicyID:      policy.ID,
		}

		ans = append(ans, red)
	}

	return ans
}

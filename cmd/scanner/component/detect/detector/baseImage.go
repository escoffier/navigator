package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckBaseImage(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.BaseImage.Enable {
		return ans
	}

	if util.ExistBit1(data.Image.Flag, imagesecModel.FlagBaseImage) {
		return ans
	}

	if data.BaseImageCnt <= 0 {
		red := &imagesecModel.ImageDetectResult{
			DetectType:    imagesecModel.DetectTypeBaseImageRule,
			Flag:          util.SetBit1(0, imagesecModel.FlagDetectException),
			ImageUniqueID: data.Image.UniqueID,
			UniqueTarget:  data.Image.UniqueID,
			PolicyID:      policy.ID,
		}

		switch policy.BaseImage.Action {
		case imagesecModel.DeployActionBlock:
			red.Flag = util.SetBit1(red.Flag, imagesecModel.FlagDetectDeployActionBlock)
		case imagesecModel.DeployActionAlarm:
			red.Flag = util.SetBit1(red.Flag, imagesecModel.FlagDetectDeployActionAlarm)
		}
		ans = append(ans, red)
	}

	return ans
}

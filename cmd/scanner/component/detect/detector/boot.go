package detector

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageUser(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.RootBoot.Enable {
		return ans
	}
	if data.Image.User == consts.BootRootUser || data.Image.User == "" {
		red := &imagesecModel.ImageDetectResult{
			DetectType:    imagesecModel.DetectTypeRootRule,
			Flag:          util.SetBit1(0, imagesecModel.FlagDetectException),
			ImageUniqueID: data.Image.UniqueID,
			UniqueTarget:  data.Image.UniqueID,
			PolicyID:      policy.ID,
		}

		switch policy.RootBoot.Action {
		case imagesecModel.DeployActionBlock:
			red.Flag = util.SetBit1(red.Flag, imagesecModel.FlagDetectDeployActionBlock)
		case imagesecModel.DeployActionAlarm:
			red.Flag = util.SetBit1(red.Flag, imagesecModel.FlagDetectDeployActionAlarm)
		}
		ans = append(ans, red)
	}

	return ans
}

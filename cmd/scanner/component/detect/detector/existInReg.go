package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckExistInReg(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable ||
		!policy.ExistInReg.Enable || data.Image.ImageFromType == imagesecModel.ImageFromRegistry {
		return ans
	}

	if len(data.ImageInReg) == 0 || len(data.ImageInReg[0].RegIds) == 0 {
		red := &imagesecModel.ImageDetectResult{
			DetectType:    imagesecModel.DetectTypeExistInRegRule,
			Flag:          util.SetBit1(0, imagesecModel.FlagDetectException),
			ImageUniqueID: data.Image.UniqueID,
			UniqueTarget:  data.Image.UniqueID,
			PolicyID:      policy.ID,
		}
		ans = append(ans, red)
	}

	return ans
}

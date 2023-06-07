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
	if !policy.RootBootEnable {
		return ans
	}
	if data.Image.User == consts.BootRootUser || data.Image.User == "" {
		ans = append(ans, &imagesecModel.ImageDetectResult{
			ID:            0,
			DetectType:    imagesecModel.DetectTypeRootRule,
			Flag:          util.SetBit1(0, imagesecModel.FlagDetectException),
			ImageUniqueID: data.Image.UniqueID,
			PolicyID:      policy.ID,
		})
	}

	return ans
}

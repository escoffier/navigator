package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageWebshell(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if !policy.Webshell.Enable {
		return ans
	}
	white := policy.Webshell.White

	certain, maybe := false, false

	for i := range policy.Webshell.RiskLevel {
		if policy.Webshell.RiskLevel[i] == imagesecModel.WebshellRiskLevelCertain {
			certain = true
		}
		if policy.Webshell.RiskLevel[i] == imagesecModel.WebshellRiskLevelMaybe {
			maybe = true
		}
	}

	for i := range data.Webshell {
		ws := data.Webshell[i]
		if util.ExistInStringSlice(white, data.Webshell[i].Filename) {
			ans = append(ans, &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeWebshellRule,
				Flag:          util.SetBit1(0, imagesecModel.FlagDetectInWhite),
				UniqueTarget:  data.Webshell[i].UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			})
			continue
		}
		if (ws.RiskLevel == imagesecModel.WebshellRiskLevelCertain && (maybe || certain)) ||
			(ws.RiskLevel == imagesecModel.WebshellRiskLevelMaybe && maybe) {
			ans = append(ans, &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeWebshellRule,
				Flag:          util.SetBit1(0, imagesecModel.FlagDetectException),
				UniqueTarget:  data.Webshell[i].UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			})
		}
	}
	return ans
}

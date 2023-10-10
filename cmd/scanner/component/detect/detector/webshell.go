package detector

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageWebshell(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.Webshell.Enable || len(data.Webshell) == 0 {
		return ans
	}
	white := policy.Webshell.White

	certain, maybe := false, false

	for _, lev := range policy.Webshell.RiskLevel {
		if lev == imagesecModel.WebshellRiskLevelCertain {
			certain = true
		}
		if lev == imagesecModel.WebshellRiskLevelMaybe {
			maybe = true
		}
	}

	for i := range data.Webshell {
		ws := data.Webshell[i]
		var flag uint64

		if util.ExistInStringSlice(white, data.Webshell[i].Filename) {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		}
		if (ws.RiskLevel == imagesecModel.WebshellRiskLevelCertain && certain) ||
			(ws.RiskLevel == imagesecModel.WebshellRiskLevelMaybe && maybe) {

			flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
		}
		if util.ExistBit1(flag, imagesecModel.FlagDetectException) && !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) {
			switch policy.Webshell.Action {
			case imagesecModel.DeployActionBlock:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
			case imagesecModel.DeployActionAlarm:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
			}
		}

		if flag > 0 {
			red := &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeWebshellRule,
				Flag:          flag,
				UniqueTarget:  data.Webshell[i].UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			}

			ans = append(ans, red)
		}
	}
	return ans
}

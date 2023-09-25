package detector

import (
	"context"
	"strings"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageEnv(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.Env.Enable || len(data.Env) == 0 {
		return ans
	}
	for i := range data.Env {
		v := data.Env[i]
		var flag uint64

		if policy.Env.CheckPassword && ContainPassword(v.Key, v.Value) {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
			flag = util.SetBit1(flag, imagesecModel.FlagDetectEnvHasPasswd)
		}

		if util.ExistInStringSlice(policy.Env.Black, v.Key) {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
		}

		if util.ExistBit1(flag, imagesecModel.FlagDetectException) {
			switch policy.Env.Action {
			case imagesecModel.DeployActionBlock:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
			case imagesecModel.DeployActionAlarm:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
			}
		}

		if flag > 0 {
			red := &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeEnvRule,
				Flag:          flag,
				UniqueTarget:  v.UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			}

			ans = append(ans, red)
		}
	}
	return ans
}

func ContainPassword(name, value string) bool {
	name = strings.ToLower(name)
	value = strings.ToLower(value)
	if strings.Contains(name, "password") || strings.Contains(name, "passwd") ||
		strings.Contains(value, "password") || strings.Contains(value, "passwd") {
		return true
	}
	return false
}

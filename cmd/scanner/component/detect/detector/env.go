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
	if !policy.Env.Enable {
		return ans
	}
	for i := range data.Env {
		v := data.Env[i]
		var flag uint64
		if ContainPassword(v.Key, v.Value) {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectEnvHasPasswd)
		}
		if policy.Env.CheckPassword && ContainPassword(v.Key, v.Value) {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
		}
		if util.ExistInStringSlice(policy.Env.Black, v.Key) {
			flag = util.SetBit1(util.SetBit1(flag, imagesecModel.FlagDetectInBlack), imagesecModel.FlagDetectException)
		}
		ans = append(ans, &imagesecModel.ImageDetectResult{
			DetectType:    imagesecModel.DetectTypeEnvRule,
			Flag:          flag,
			UniqueTarget:  v.UniqueID,
			ImageUniqueID: data.Image.UniqueID,
			PolicyID:      policy.ID,
		})
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

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
		if policy.Env.CheckPassword {
			if ContainPassword(v.Key, v.Value) {
				ans = append(ans, &imagesecModel.ImageDetectResult{

					DetectType:    imagesecModel.DetectTypeEnvRule,
					Flag:          util.SetBit1(0, imagesecModel.FlagDetectEnvHasPasswd),
					UniqueTarget:  v.UniqueID,
					ImageUniqueID: data.Image.UniqueID,
					PolicyID:      policy.ID,
				})
			}
		}
		if util.ExistInStringSlice(policy.Env.Black, v.Key) {
			ans = append(ans, &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeEnvRule,
				Flag:          util.SetBit1(util.SetBit1(0, imagesecModel.FlagDetectInBlack), imagesecModel.FlagDetectException),
				UniqueTarget:  v.UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			})
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

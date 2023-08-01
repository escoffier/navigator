package detector

import (
	"context"
	"strings"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImagePkg(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || len(data.Pkg) == 0 {
		return ans
	}
	pkgBlack := policy.Pkg.Black
	blackPkgLicense := policy.License.Black

	for i := range data.Pkg {
		var flag uint64
		if policy.Pkg.Enable {
			for j := range pkgBlack {
				if data.Pkg[i].Name == pkgBlack[j].Name && (data.Pkg[i].Version == pkgBlack[j].InstallVersion ||
					pkgBlack[j].InstallVersion == "") {

					flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
					flag = util.SetBit1(flag, imagesecModel.FlagDetectInBlack)

					switch policy.Pkg.Action {
					case imagesecModel.DeployActionBlock:
						flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
					case imagesecModel.DeployActionAlarm:
						flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
					}
				}
			}
		}

		if policy.PkgLicense.Enable {
			license := data.Pkg[i].License

			for j := range blackPkgLicense {
				bl := blackPkgLicense[j]
				if strings.Contains(license, bl) {
					flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
					flag = util.SetBit1(flag, imagesecModel.FlagDetectInBlack)
					flag = util.SetBit1(flag, imagesecModel.FlagDetectExceptionPkgLicense)

					switch policy.PkgLicense.Action {
					case imagesecModel.DeployActionBlock:
						flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
					case imagesecModel.DeployActionAlarm:
						flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
					}
				}
			}
		}

		if flag > 0 {
			red := &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypePkgRule,
				Flag:          flag,
				UniqueTarget:  data.Pkg[i].UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			}
			ans = append(ans, red)
		}
	}
	return ans
}

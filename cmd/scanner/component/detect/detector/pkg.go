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
		pk := data.Pkg[i]
		if policy.Pkg.Enable {
			for j := range pkgBlack {
				pb := pkgBlack[j]
				if pk.Name == pb.Name && (pk.Version == pb.InstallVersion || pb.InstallVersion == "") {

					flag = util.SetBit1(flag, imagesecModel.FlagDetectException)

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
			lic := data.Pkg[i].License

			for j := range blackPkgLicense {
				bl := blackPkgLicense[j]

				if strings.Contains(lic, bl) {
					// flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
					// 新变动，不容许的开源协议，不算异常软件包
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
				UniqueTarget:  pk.UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			}
			ans = append(ans, red)
		}
	}
	return ans
}

package detector

import (
	"context"
	"strings"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageVuln(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {
	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.VulnDB.Enable || len(data.Vuln) == 0 {
		return ans
	}
	white := policy.VulnDB.White
	black := policy.VulnDB.Black
	vulns := data.Vuln

	for i := range vulns {
		var flag uint64
		vu := vulns[i]

		if policy.VulnDB.IgnoreUnfixed && vu.FixedVersion == "" {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		}
		if policy.VulnDB.IgnoreKernelVuln && util.ExistBit1(vu.Flag, imagesecModel.VulnFlagKernel) {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		}
		if policy.VulnDB.IgnoreLangVuln && util.ExistBit1(vu.Flag, imagesecModel.VulnFlagClassLangPkg) {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		}

		whiteAdd, blackAdd := false, false
		for _, wh := range white {
			if vu.Name == wh.VulnID {
				whiteAdd = true
				if wh.PkgName != "" && vu.PkgName != wh.PkgName {
					whiteAdd = false
				}
				if wh.PkgVersion != "" && vu.PkgVersion != wh.PkgVersion {
					whiteAdd = false
				}
			}
		}
		if whiteAdd {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		}

		for _, wh := range black {
			if vu.Name == wh.VulnID {
				blackAdd = true
				if wh.PkgName != "" && vu.PkgName != wh.PkgName {
					blackAdd = false
				}
				if wh.PkgVersion != "" && vu.PkgVersion != wh.PkgVersion {
					blackAdd = false
				}
			}
		}

		if !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) && blackAdd {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
		}

		if !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) && (policy.VulnDB.Severity != "" &&
			imagesecModel.GetSeverityInt(strings.ToUpper(policy.VulnDB.Severity)) <= vu.SeverityInt) {

			flag = util.SetBit1(util.SetBit1(flag, imagesecModel.GetVulnSeverityDetectFlag(vu.SeverityInt)),
				imagesecModel.FlagDetectException)
		}

		if util.ExistBit1(flag, imagesecModel.FlagDetectException) && !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) {
			switch policy.VulnDB.Action {
			case imagesecModel.DeployActionBlock:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
			case imagesecModel.DeployActionAlarm:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
			}
		}

		if flag > 0 {
			red := &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeVulnRule,
				Flag:          flag,
				UniqueTarget:  vu.UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			}

			ans = append(ans, red)
		}
	}

	return ans
}

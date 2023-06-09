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
	if !policy.Vuln.Enable {
		return ans
	}
	white := policy.Vuln.White
	black := policy.Vuln.Black
	vulns := data.Vuln
	for i := range vulns {
		var flag uint64
		if policy.Vuln.IgnoreUnfixed && vulns[i].FixedVersion == "" ||
			policy.Vuln.IgnoreKernelVuln && util.ExistBit1(vulns[i].Flag, imagesecModel.VulnFlagKernelPkg) ||
			policy.Vuln.IgnoreLangVuln && util.ExistBit1(vulns[i].Flag, imagesecModel.VulnFlagClassLangPkg) {
			continue
		}

		whiteAdd, blackAdd := false, false
		for _, wh := range white {
			if vulns[i].Name == wh.VulnID {
				whiteAdd = true
				if wh.PkgName != "" && vulns[i].PkgName != wh.PkgName {
					whiteAdd = false
				}
				if wh.PkgVersion != "" && vulns[i].PkgVersion != wh.PkgVersion {
					whiteAdd = false
				}
			}
		}
		if whiteAdd {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		}

		for _, wh := range black {
			if vulns[i].Name == wh.VulnID {
				blackAdd = true
				if wh.PkgName != "" && vulns[i].PkgName != wh.PkgName {
					blackAdd = false
				}
				if wh.PkgVersion != "" && vulns[i].PkgVersion != wh.PkgVersion {
					blackAdd = false
				}
			}
		}

		if !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) && blackAdd {
			flag = util.SetBit1(util.SetBit1(flag, imagesecModel.FlagDetectInBlack), imagesecModel.FlagDetectException)
		}

		if !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) && (policy.Vuln.Severity != "" &&
			imagesecModel.GetSeverityInt(strings.ToUpper(policy.Vuln.Severity)) <= vulns[i].SeverityInt) {
			flag = util.SetBit1(util.SetBit1(flag, imagesecModel.GetVulnSeverityDetectFlag(vulns[i].SeverityInt)),
				imagesecModel.FlagDetectException)
		}
		if flag > 0 {
			ans = append(ans, &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeVulnRule,
				Flag:          flag,
				UniqueTarget:  vulns[i].UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			})
		}
	}

	return ans
}

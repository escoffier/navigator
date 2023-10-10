package detect

import (
	"fmt"
	"sort"
	"strings"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func Uint64ToString(ans []uint64) string {
	sort.Slice(ans, func(i, j int) bool {
		return ans[i] < ans[j]
	})

	aa := make([]string, 0)
	for i := range ans {
		a := fmt.Sprintf("%d", ans[i])
		aa = append(aa, a)
	}
	return strings.Join(aa, ",")
}

func GetImagePolicyType(im imagesecModel.Image) string {
	switch im.ImageFromType {
	case imagesecModel.ImageFromRegistry:
		return imagesecModel.ConfigTypeRegScanImage
	case imagesecModel.ImageFromNode:
		return imagesecModel.ConfigTypeNodeScanImage
	}
	return ""
}

func MergeDetectResult(det PolicyDetectResult2, res PolicyDetectResult) PolicyDetectResult2 {

	for detectType, detectResult := range res {
		if det[detectType] == nil {
			det[detectType] = make(map[uint64]*imagesecModel.ImageDetectResult)
		}
		for j := range detectResult {
			dr := detectResult[j]

			tar, ok := det[detectType][dr.UniqueTarget]
			if !ok {
				det[detectType][dr.UniqueTarget] = dr
				continue
			}
			if util.ExistBit1(dr.Flag, imagesecModel.FlagDetectDeployActionBlock) {
				tar.Flag = util.SetBit1(tar.Flag, imagesecModel.FlagDetectDeployActionBlock)
				tar.Flag = util.SetBit0(tar.Flag, imagesecModel.FlagDetectDeployActionAlarm)
			}
			det[detectType][dr.UniqueTarget] = tar
		}
	}
	return det
}

type PolicyDetectResult map[string][]*imagesecModel.ImageDetectResult

// detectType-->targetUniqueID->target
type PolicyDetectResult2 map[string]map[uint64]*imagesecModel.ImageDetectResult

func check(res PolicyDetectResult2, flag uint64, ruleType string, exceptIdx uint64) uint64 {
	flag = util.SetBit0(flag, exceptIdx)
	for _, dr := range res[ruleType] {
		if util.ExistBit1(dr.Flag, imagesecModel.FlagDetectException) {
			flag = util.SetBit1(flag, exceptIdx)
			break
		}
	}

	// 对于软件包，需要判断软件包版本号和license
	if ruleType == imagesecModel.DetectTypePkgRule {
		flag = util.SetBit0(flag, imagesecModel.FlagHasExceptionPkgLicense)
		for _, dr := range res[ruleType] {
			if util.ExistBit1(dr.Flag, imagesecModel.FlagDetectExceptionPkgLicense) {
				flag = util.SetBit1(flag, imagesecModel.FlagHasExceptionPkgLicense)
				break
			}
		}
	}

	return flag
}

func GenImageIssueFlag(res PolicyDetectResult2, flag uint64) uint64 {
	flag = check(res, flag, imagesecModel.DetectTypeVulnRule, imagesecModel.FlagHasExceptionVuln)
	flag = check(res, flag, imagesecModel.DetectTypeSensRule, imagesecModel.FlagHasExceptionSensitive)
	flag = check(res, flag, imagesecModel.DetectTypeMalwareRule, imagesecModel.FlagHasExceptionMalware)
	flag = check(res, flag, imagesecModel.DetectTypePkgRule, imagesecModel.FlagHasExceptionPKG)
	flag = check(res, flag, imagesecModel.DetectTypeWebshellRule, imagesecModel.FlagHasExceptionWebshell)
	flag = check(res, flag, imagesecModel.DetectTypeRootRule, imagesecModel.FlagDetectExceptionBoot)
	flag = check(res, flag, imagesecModel.DetectTypeEnvRule, imagesecModel.FlagHasExceptionEnv)
	flag = check(res, flag, imagesecModel.DetectTypeBaseImageRule, imagesecModel.FlagNotExitBaseImage)
	flag = check(res, flag, imagesecModel.DetectTypeTrustedImageRule, imagesecModel.FlagImageDetectUnTrusted)
	flag = check(res, flag, imagesecModel.DetectTypeLicenseRule, imagesecModel.FlagHasExceptionLicense)
	flag = check(res, flag, imagesecModel.DetectTypeExistInRegRule, imagesecModel.FlagImageDetectNotExitINReg)

	return flag
}

var allPolicy []*imagesecModel.SecurityPolicy // 程序内缓存

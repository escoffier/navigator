package detector

import (
	"context"
	"regexp"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func CheckImageSensitive(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.Sensitive.Enable || len(data.Sensitive) == 0 {
		return ans
	}
	if policy.Sensitive.AllWhite {
		return CheckImageSensitiveAllWhite(ctx, data, policy)
	}

	if policy.Sensitive.AllBlack {
		return CheckImageSensitiveAllBlock(ctx, data, policy)
	}

	sess := data.Sensitive
	white := policy.Sensitive.White
	black := policy.Sensitive.Black
	whiteReg := make([]*regexp.Regexp, 0)
	blackReg := make([]*regexp.Regexp, 0)

	if !policy.Sensitive.AllWhite {
		for i := range white {
			compile, err := regexp.Compile(white[i])
			if err != nil {
				logging.Get().Err(err).Str("module", "detectImage").Str("white", white[i]).Msg("Compile")
				continue
			}
			whiteReg = append(whiteReg, compile)
		}
	}

	if !policy.Sensitive.AllBlack {
		for i := range black {
			compile, err := regexp.Compile(black[i])
			if err != nil {
				logging.Get().Err(err).Str("module", "detectImage").Str("white", black[i]).Msg("Compile")
				continue
			}
			blackReg = append(blackReg, compile)
		}
	}

	for i := range sess {
		ses := sess[i]
		var flag uint64
		if policy.Sensitive.AllWhite {
			flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		}
		for j := range whiteReg {
			wh := whiteReg[j]
			if wh.FindString(ses.Filename) != "" {
				flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
			}
		}

		if !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) {
			if policy.Sensitive.AllBlack {
				flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
			}

			for j := range blackReg {
				bl := blackReg[j]
				if bl.FindString(ses.Filename) != "" {
					flag = util.SetBit1(flag, imagesecModel.FlagDetectException)
				}
			}
		}

		if util.ExistBit1(flag, imagesecModel.FlagDetectException) && !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) {
			switch policy.Sensitive.Action {
			case imagesecModel.DeployActionBlock:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
			case imagesecModel.DeployActionAlarm:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
			}
		}
		if flag > 0 {
			red := &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeSensRule,
				Flag:          flag,
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			}

			ans = append(ans, red)
		}
	}

	return ans
}

func CheckImageSensitiveAllWhite(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.Sensitive.Enable {
		return ans
	}
	if !policy.Sensitive.AllWhite {
		return ans
	}

	sess := data.Sensitive
	for i := range sess {
		ses := sess[i]
		var flag uint64
		flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
		flag = util.SetBit0(flag, imagesecModel.FlagDetectException)
		red := &imagesecModel.ImageDetectResult{
			DetectType:    imagesecModel.DetectTypeSensRule,
			Flag:          flag,
			UniqueTarget:  ses.UniqueID,
			ImageUniqueID: data.Image.UniqueID,
			PolicyID:      policy.ID,
		}

		ans = append(ans, red)
	}

	return ans
}

func CheckImageSensitiveAllBlock(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult {

	ans := make([]*imagesecModel.ImageDetectResult, 0)
	if policy == nil || data == nil || data.Image.ID <= 0 || !policy.Enable || !policy.Sensitive.Enable {
		return ans
	}
	if !policy.Sensitive.AllBlack {
		return ans
	}

	sess := data.Sensitive
	for i := range sess {
		ses := sess[i]
		var flag uint64
		flag = util.SetBit1(flag, imagesecModel.FlagDetectException)

		if util.ExistBit1(flag, imagesecModel.FlagDetectException) && !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) {
			switch policy.Sensitive.Action {
			case imagesecModel.DeployActionBlock:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionBlock)
			case imagesecModel.DeployActionAlarm:
				flag = util.SetBit1(flag, imagesecModel.FlagDetectDeployActionAlarm)
			}
		}

		red := &imagesecModel.ImageDetectResult{
			DetectType:    imagesecModel.DetectTypeSensRule,
			Flag:          flag,
			UniqueTarget:  ses.UniqueID,
			ImageUniqueID: data.Image.UniqueID,
			PolicyID:      policy.ID,
		}
		ans = append(ans, red)
	}
	return ans
}

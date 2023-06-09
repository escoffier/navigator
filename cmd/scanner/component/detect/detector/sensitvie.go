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
	if !policy.Sensitive.Enable {
		return ans
	}
	sess := data.Sensitive
	white := policy.Sensitive.White
	black := policy.Sensitive.Black
	whiteReg := make([]*regexp.Regexp, 0)
	blackReg := make([]*regexp.Regexp, 0)

	for i := range white {
		compile, err := regexp.Compile(white[i])
		if err != nil {
			logging.Get().Err(err).Str("white", white[i]).Msg("Compile")
			continue
		}
		whiteReg = append(whiteReg, compile)
	}

	for i := range black {
		compile, err := regexp.Compile(black[i])
		if err != nil {
			logging.Get().Err(err).Str("white", black[i]).Msg("Compile")
			continue
		}
		blackReg = append(blackReg, compile)
	}

	for i := range sess {
		ses := sess[i]
		var flag uint64
		for j := range whiteReg {
			wh := whiteReg[j]
			if wh.FindString(ses.Name) != "" {
				flag = util.SetBit1(flag, imagesecModel.FlagDetectInWhite)
			}
		}

		if !util.ExistBit1(flag, imagesecModel.FlagDetectInWhite) {
			for j := range blackReg {
				bl := blackReg[j]
				if bl.FindString(ses.Name) != "" {
					flag = util.SetBit1(util.SetBit1(flag, imagesecModel.FlagDetectInBlack), imagesecModel.FlagDetectException)
				}
			}
		}

		if flag > 0 {
			ans = append(ans, &imagesecModel.ImageDetectResult{
				DetectType:    imagesecModel.DetectTypeSensRule,
				Flag:          flag,
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: data.Image.UniqueID,
				PolicyID:      policy.ID,
			})
		}

	}

	return ans
}

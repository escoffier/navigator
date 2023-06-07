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

	for i := range white {
		compile, err := regexp.Compile(white[i])
		if err != nil {
			logging.Get().Err(err).Str("white", white[i]).Msg("Compile")
			continue
		}
		whiteReg = append(whiteReg, compile)
	}

	blackReg := make([]*regexp.Regexp, 0)

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
		inWhite := false
		for j := range whiteReg {
			wh := whiteReg[j]
			if wh.FindString(ses.Name) != "" {
				inWhite = true
				ans = append(ans, &imagesecModel.ImageDetectResult{
					DetectType:    imagesecModel.DetectTypeSensRule,
					Flag:          util.SetBit1(0, imagesecModel.FlagDetectInWhite),
					UniqueTarget:  ses.UniqueID,
					ImageUniqueID: data.Image.UniqueID,
					PolicyID:      policy.ID,
				})
			}
		}
		// 白名单的优先级最高
		if !inWhite {
			for j := range blackReg {
				wh := blackReg[j]
				findString := wh.FindString(ses.Name)
				if findString != "" {
					ans = append(ans, &imagesecModel.ImageDetectResult{
						DetectType:    imagesecModel.DetectTypeSensRule,
						Flag:          util.SetBit1(util.SetBit1(0, imagesecModel.FlagDetectInBlack), imagesecModel.FlagDetectException),
						UniqueTarget:  ses.UniqueID,
						ImageUniqueID: data.Image.UniqueID,
						PolicyID:      policy.ID,
					})
				}
			}
		}
	}

	return ans
}

package image

import (
	"strings"

	"github.com/docker/docker/api/types"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/checksum"
	"gitlab.com/security-rd/go-pkg/logging"
)

type imageInfo struct {
	WhiteList []checksum.WhitelistFile
}

func MakeWhiteListByOverLay(image types.ImageInspect) (imageInfo, error) {

	// "Merged Dir" should be last element
	imageDirKeys := []string{"MergedDir", "WorkDir", "UpperDir", "LowerDir"}
	imageDir := make([]string, 0)
	for _, key := range imageDirKeys {
		tmpDirs := strings.Split(image.GraphDriver.Data[key], ":")
		for _, v := range tmpDirs {
			if v == "" {
				continue
			}
			imageDir = append(imageDir, v)
		}
	}

	whiteList := checksum.WalkDir(imageDir)
	logging.Get().Debug().Msgf("white list len: %d\n", len(whiteList))
	// dumpWhitelist(whiteList, whiteListName)
	imageInfo := imageInfo{WhiteList: whiteList}
	return imageInfo, nil
}

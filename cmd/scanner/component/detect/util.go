package detect

import (
	"fmt"
	"sort"
	"strings"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
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

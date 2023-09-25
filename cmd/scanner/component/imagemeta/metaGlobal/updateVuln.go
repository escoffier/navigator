package metaGlobal

import (
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type VulnUpdate struct {
	AddImage chan *imagesecModel.Image
	SubImage chan *imagesecModel.Image
}

var vulnUpdate *VulnUpdate

func GetVulnUpdate() *VulnUpdate {
	if vulnUpdate != nil {
		return vulnUpdate
	}
	ans := &VulnUpdate{
		AddImage: make(chan *imagesecModel.Image),
		SubImage: make(chan *imagesecModel.Image),
	}
	vulnUpdate = ans
	return vulnUpdate
}

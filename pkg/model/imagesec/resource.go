package imagesec

import (
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type RawContainer struct {
	ClusterName        string                   `json:"clusterName"`
	TensorRawContainer model.TensorRawContainer `json:"tensorRawContainer"`
}

type RelatedImageRes struct {
	ImageID       int64            `json:"imageID"`
	ImageFromType string           `json:"imageFromType"`
	ImageUniqueID uint64           `json:"imageUniqueID,string"`
	Image         string           `json:"image"`
	Digest        string           `json:"digest"`
	Registry      []RegistrySimple `json:"registry"`
	Node          []*NodeInfo      `json:"node"`
	Container     []string         `json:"container"`
	ImageUUID     uint32           `json:"imageUUID"`
}

func (vi *RelatedImageRes) HasKeyword(w string) bool {
	if strings.Contains(vi.Image, w) {
		return true
	}
	for i := range vi.Container {
		if strings.Contains(vi.Container[i], w) {
			return true
		}
	}
	for i := range vi.Registry {
		if strings.Contains(vi.Registry[i].Name, w) || strings.Contains(vi.Registry[i].Url, w) {
			return true
		}
	}

	for i := range vi.Node {
		if strings.Contains(vi.Node[i].Hostname, w) || strings.Contains(vi.Node[i].ClusterName, w) {
			return true
		}
	}

	return false
}

package scanner_ci

import (
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"
)

// ImageArtifact used for ci-tool request to ci-controller
type ImageArtifact struct {
	UUID          string                      `json:"uuid"`
	ImageName     string                      `json:"image_name"`      // full image name: [url]/[repo]:[tag]
	Artifact      ftypes.ArtifactDetail       `json:"artifact"`        // packages in image
	ImageDetail   types.ImageInspect          `json:"image_detail"`    // image inspect result,include config,graph path etc
	ImageLayers   []image.HistoryResponseItem `json:"image_layers"`    // image layers
	GraphDataPath []string                    `json:"graph_data_path"` // sorted graph path,eg: /var/lib/docker/overlayer2/xxx,/var/lib/docker/overlayer2/yyy
}

// ImageVulnerabilities used for ci-controller response to ci-tool
type ImageVulnerabilities struct {
	UUID      string         `json:"uuid"`
	ImageName string         `json:"image_name"`
	Results   report.Results `json:"result"`
}

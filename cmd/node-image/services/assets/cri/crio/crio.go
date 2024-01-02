package crio

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/pkg/errors"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"

	criApi "k8s.io/cri-api/pkg/apis"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DriverConfig struct {
	Endpoint string `json:"endpoint"`
}

type Driver struct {
	config      DriverConfig
	runClient   criApi.RuntimeService
	ImageClient criApi.ImageManagerService
	sync.Mutex
}

func NewCRIODriver(config DriverConfig) (*Driver, error) {
	d := &Driver{}

	d.config = config
	d.config.Endpoint = strings.TrimSpace(d.config.Endpoint)
	if d.config.Endpoint != "" {
		_ = os.Setenv("CRIO_HOST", d.config.Endpoint)
	}
	uri := GetCRIOdAddr()
	// crio client
	runClient, err := remote.NewRemoteRuntimeService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new NewRemoteRuntimeService failed, %v", err)
	}
	imageClient, err := remote.NewRemoteImageService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new NewRemoteImageService failed, %v", err)
	}

	d.runClient = runClient
	d.ImageClient = imageClient
	return d, nil
}

func (s *Driver) ListImages(ctx context.Context) ([]imagesecModel.ImageSummary, error) {
	images, err := s.ImageClient.ListImages(nil)
	if err != nil {
		return nil, err
	}
	var imageList []imagesecModel.ImageSummary
	for _, ima := range images {
		imageList = append(imageList, imagesecModel.ImageSummary{
			ID:          ima.Id,
			RepoDigests: ima.RepoDigests,
			RepoTags:    ima.RepoTags,
		})
	}
	return imageList, nil
}

func (s *Driver) InspectImage(ctx context.Context, namespace string, imageID string) (types.ImageInspect, error) {
	ima, imageInfo, err := nodeinfo.GetCrioImageDetail(s.ImageClient, imageID, true)
	if err != nil {
		return types.ImageInspect{}, fmt.Errorf("crio GetImageInspect failed. %v", err)
	}
	var fs types.RootFS
	fs.Type = imageInfo.ImageSpec.Rootfs.Type
	for _, d := range imageInfo.ImageSpec.Rootfs.DiffIds {
		fs.Layers = append(fs.Layers, d)
	}
	result := types.ImageInspect{
		ID:          imageID,
		RepoTags:    ima.GetRepoTags(),
		RepoDigests: ima.GetRepoDigests(),
		Created:     imageInfo.ImageSpec.Created.Format(time.RFC3339Nano),
		Config: &container.Config{
			Env:    imageInfo.ImageSpec.Config.Env,
			Cmd:    imageInfo.ImageSpec.Config.Cmd,
			Labels: imageInfo.ImageSpec.Config.Labels,
		},
		Architecture: imageInfo.ImageSpec.Architecture,
		Os:           imageInfo.ImageSpec.Os,
		Size:         int64(ima.Size_),
		VirtualSize:  int64(ima.Size_),
		RootFS:       fs,
	}
	return result, nil
}

func (s *Driver) ImageLayers(ctx context.Context, namespace string, imageID string) ([]image.HistoryResponseItem, error) {
	_, imageInfo, err := nodeinfo.GetCrioImageDetail(s.ImageClient, imageID, true)
	if err != nil {
		return nil, fmt.Errorf("crio ImageHistory failed.%v", err)
	}
	var result []image.HistoryResponseItem
	for _, his := range imageInfo.ImageSpec.History {
		result = append(result, image.HistoryResponseItem{
			Comment:   his.Comment,
			Created:   his.Created.Unix(),
			CreatedBy: his.CreatedBy,
		})
	}
	return result, nil
}

func (s *Driver) Type() string {
	return consts.CrioRuntime
}

type CRIOImage struct {
	Architecture string `json:"architecture"`
	Config       struct {
		Env    []string `json:"Env"`
		Cmd    []string `json:"Cmd"`
		Labels struct {
			OrgOpencontainersImageRefName string `json:"org.opencontainers.image.ref.name"`
			OrgOpencontainersImageVersion string `json:"org.opencontainers.image.version"`
		} `json:"Labels"`
		ArgsEscaped bool        `json:"ArgsEscaped"`
		OnBuild     interface{} `json:"OnBuild"`
	} `json:"config"`
	Created time.Time `json:"created"`
	History []struct {
		Created    time.Time `json:"created"`
		CreatedBy  string    `json:"created_by"`
		EmptyLayer bool      `json:"empty_layer,omitempty"`
		Comment    string    `json:"comment,omitempty"`
	} `json:"history"`
	Os     string `json:"os"`
	Rootfs struct {
		Type    string   `json:"type"`
		DiffIds []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type LayerItem struct {
	Id                   string    `json:"id"`
	Parent               string    `json:"parent"`
	Created              time.Time `json:"created"`
	CompressedDiffDigest string    `json:"compressed-diff-digest"`
	CompressedSize       int       `json:"compressed-size"`
	DiffDigest           string    `json:"diff-digest"`
	DiffSize             int       `json:"diff-size"`
	Compression          int       `json:"compression"`
	Uidset               []int     `json:"uidset"`
	Gidset               []int     `json:"gidset"`
}

func GetCRIOdAddr() string {
	uri := os.Getenv(consts.EnvCRIOSocketAddr)
	if len(uri) == 0 {
		uri = consts.DefaultCRIOSocket
	}
	return uri
}

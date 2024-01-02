package assets

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/assets/cri/containerd"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/assets/cri/crio"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/assets/cri/docker"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type Runtime interface {
	ListImages(ctx context.Context) ([]imagesecModel.ImageSummary, error)
	InspectImage(ctx context.Context, ns, imageID string) (types.ImageInspect, error)
	ImageLayers(ctx context.Context, ns, imageID string) ([]image.HistoryResponseItem, error)
	Type() string
}

func IsUnixSockFile(filename string) bool {
	if strings.HasPrefix(filename, "unix://") {
		filename = filename[len("unix://"):]
	}

	info, err := os.Stat(filename)
	if err != nil {
		logging.Get().Err(err).Msg("check unix socket file failed")
		return false
	}
	return (info.Mode() & os.ModeSocket) != 0
}

func CreateRuntimeCli() (Runtime, error) {
	dockerUir := os.Getenv(consts.ENVDockerSocketAddr)

	if dockerUir != "" && IsUnixSockFile(dockerUir) {
		rt, err := docker.NewDriver(docker.DriverConfig{Endpoint: dockerUir})
		if err == nil {
			logging.Get().Info().Msg("create docker runtime success")
			return rt, nil
		}
	}

	containerdUri := os.Getenv(consts.ENVContainerdSocketAddr)
	if containerdUri != "" && IsUnixSockFile(containerdUri) {
		rt, err := containerd.NewDriver(containerd.DriverConfig{Endpoint: containerdUri})
		if err == nil {
			logging.Get().Info().Msg("create containerd runtime success")
			return rt, nil
		}
	}

	crioUri := os.Getenv(consts.EnvCRIOSocketAddr)
	if crioUri != "" && IsUnixSockFile(crioUri) {
		rt, err := crio.NewCRIODriver(crio.DriverConfig{Endpoint: crioUri})
		if err == nil {
			logging.Get().Info().Msg("create crio runtime success")
			return rt, nil
		}
	}

	return nil, fmt.Errorf("not support cri type")
}

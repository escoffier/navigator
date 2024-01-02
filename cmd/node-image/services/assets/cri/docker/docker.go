package docker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DriverConfig struct {
	Endpoint string `json:"endpoint"`
}

type Driver struct {
	Config    DriverConfig
	DockerCli *client.Client
}

func (d *Driver) ListImages(ctx context.Context) ([]imagesecModel.ImageSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, consts.DockerRequestTimeout*time.Second)
	defer cancel()
	images, err := d.DockerCli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list images failed:%v", err)
	}
	var all []imagesecModel.ImageSummary
	for i := range images {
		all = append(all, imagesecModel.ImageSummary{
			Namespace:   "",
			ID:          images[i].ID,
			RepoDigests: images[i].RepoDigests,
			RepoTags:    images[i].RepoTags,
		})
	}

	return all, nil
}

func (d *Driver) InspectImage(ctx context.Context, ns, imageID string) (types.ImageInspect, error) {
	ctx, cancel := context.WithTimeout(ctx, consts.DockerRequestTimeout*time.Second)
	defer cancel()
	i, _, err := d.DockerCli.ImageInspectWithRaw(ctx, imageID)
	if err != nil {
		return types.ImageInspect{}, fmt.Errorf("get image inspect failed, %v", err)
	}
	return i, nil
}

func (d *Driver) Type() string {
	return consts.DockerRuntime
}

func (d *Driver) ImageLayers(ctx context.Context, ns, imageID string) ([]image.HistoryResponseItem, error) {
	ctx, cancel := context.WithTimeout(ctx, consts.DockerRequestTimeout*time.Second)
	defer cancel()
	history, err := d.DockerCli.ImageHistory(ctx, imageID)
	if err != nil {
		return []image.HistoryResponseItem{}, fmt.Errorf("get image history failed, %v", err)
	}
	return history, nil
}

// func init() {
// 	err := cri.Register(consts.DockerRuntime, NewDriver)
// 	if err != nil {
// 		log.Err(err).Msg("register docker driver failed")
// 		return
// 	}
//
// }

func NewDriver(config DriverConfig) (*Driver, error) {
	d := &Driver{
		Config: config,
	}

	//
	// byt, err := json.Marshal(config.Options)
	// if err != nil {
	// 	log.Err(err).Msg("marshal option failed")
	// 	return nil, err
	// }
	//
	// conf := new(DriverConfig)
	// if err := json.Unmarshal(byt, conf); err != nil {
	// 	log.Err(err).Msg("unmarshal conf failed")
	// 	return nil, err
	// }
	//
	// d.Config = conf
	d.Config.Endpoint = strings.TrimSpace(d.Config.Endpoint)
	if d.Config.Endpoint != "" {
		_ = os.Setenv(client.EnvOverrideHost, d.Config.Endpoint)
	}
	uri := os.Getenv(consts.ENVDockerSocketAddr)
	if len(uri) == 0 {
		uri = consts.DefaultDockerSocket
	}

	// docker client
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithHost(uri))
	if err != nil {
		log.Err(err).Msg("create docker client failed")
		return nil, err
	}
	d.DockerCli = dockerCli

	ctx, cancel := context.WithTimeout(context.Background(), consts.DockerRequestTimeout*time.Second)
	defer cancel()
	d.DockerCli.NegotiateAPIVersion(ctx)

	return d, nil
}

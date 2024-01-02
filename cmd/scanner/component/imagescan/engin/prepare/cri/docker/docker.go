package docker

// import (
// 	"context"
// 	"fmt"
// 	"os"
// 	"strings"
// 	"time"
//
// 	"github.com/docker/docker/api/types/image"
// 	"github.com/docker/docker/client"
// 	json "github.com/json-iterator/go"
//
// 	"github.com/docker/docker/api/types"
// 	"github.com/rs/zerolog/log"
//
// 	"scm.tensorsecurity.cn/tensorsecurity-rd/irene/consts"
// 	"scm.tensorsecurity.cn/tensorsecurity-rd/irene/local-scan/pkg/container"
// )
//
// const (
// 	dockerRequestTimeout = 3
// )
//
// type dockerDriverConfig struct {
// 	Endpoint string `json:"endpoint"`
// }
//
// type Driver struct {
// 	config    *dockerDriverConfig
// 	dockerCli *client.Client
// }
//
// func (d *Driver) InspectImage(ctx context.Context, ns, imageID string) (types.ImageInspect, error) {
// 	ctx, cancel := context.WithTimeout(ctx, dockerRequestTimeout*time.Second)
// 	defer cancel()
// 	i, _, err := d.dockerCli.ImageInspectWithRaw(ctx, imageID)
// 	if err != nil {
// 		return types.ImageInspect{}, fmt.Errorf("get image inspect failed, %v", err)
// 	}
// 	return i, nil
// }
//
// func (d *Driver) Type() string {
// 	return consts.RuntimeDocker
// }
//
// func (d *Driver) ImageLayers(ctx context.Context, ns, imageID string) ([]image.HistoryResponseItem, error) {
// 	ctx, cancel := context.WithTimeout(ctx, dockerRequestTimeout*time.Second)
// 	defer cancel()
// 	history, err := d.dockerCli.ImageHistory(ctx, imageID)
// 	if err != nil {
// 		return []image.HistoryResponseItem{}, fmt.Errorf("get image history failed, %v", err)
// 	}
// 	return history, nil
// }
//
// func (d *Driver) Info() (types.Info, error) {
// 	ctx, cancel := context.WithTimeout(context.Background(), dockerRequestTimeout*time.Second)
// 	defer cancel()
// 	info, err := d.dockerCli.Info(ctx)
// 	if err != nil {
// 		return types.Info{}, fmt.Errorf("get docker info failed:%v", err)
// 	}
// 	return info, nil
// }
//
// func init() {
// 	err := container.Register(consts.RuntimeDocker, NewDockerDriver)
// 	if err != nil {
// 		log.Err(err).Msg("register docker driver failed")
// 		return
// 	}
//
// }
//
// func NewDockerDriver(config container.RuntimeConfig) (container.Runtime, error) {
// 	var d Driver
//
// 	byt, err := json.Marshal(config.Options)
// 	if err != nil {
// 		log.Err(err).Msg("marshal option failed")
// 		return nil, err
// 	}
//
// 	conf := new(dockerDriverConfig)
// 	if err := json.Unmarshal(byt, conf); err != nil {
// 		log.Err(err).Msg("unmarshal conf failed")
// 		return nil, err
// 	}
//
// 	d.config = conf
// 	d.config.Endpoint = strings.TrimSpace(d.config.Endpoint)
// 	if d.config.Endpoint != "" {
// 		_ = os.Setenv("DOCKER_HOST", d.config.Endpoint)
// 	}
// 	uri := os.Getenv("DOCKER_SOCKET_ADDR")
// 	if len(uri) == 0 {
// 		uri = "unix:///var/run/docker.sock"
// 	}
//
// 	// docker client
// 	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithHost(uri))
// 	if err != nil {
// 		log.Err(err).Msg("create docker client failed")
// 		return nil, err
// 	}
// 	d.dockerCli = dockerCli
//
// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()
// 	d.dockerCli.NegotiateAPIVersion(ctx)
//
// 	return &d, nil
// }

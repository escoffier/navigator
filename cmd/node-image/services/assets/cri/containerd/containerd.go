package containerd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/namespaces"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	json "github.com/json-iterator/go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DriverConfig struct {
	Endpoint string `json:"endpoint"`
}

type Driver struct {
	ContainerdCli *containerd.Client
	Config        DriverConfig
}

func (s *Driver) InspectImage(ctx context.Context, namespace string, imageID string) (types.ImageInspect, error) {
	ctx, cancel := context.WithTimeout(context.Background(), consts.ContainerdRequestTimeout*time.Second)
	defer cancel()
	nsCtx := namespaces.WithNamespace(ctx, namespace)
	imSec := types.ImageInspect{}

	ima, err := s.ContainerdCli.GetImage(nsCtx, imageID)
	if err != nil {
		return imSec, fmt.Errorf("get image inspect failed,%v", err)
	}
	spec, err := ima.Spec(nsCtx)
	if err != nil {
		return imSec, fmt.Errorf("get image config failed,%v", err)
	}

	fs2, err := ima.RootFS(nsCtx)
	if err != nil {
		return imSec, fmt.Errorf("get image RootFS failed,%v", err)
	}
	fs := types.RootFS{Layers: make([]string, 0)}
	for _, d := range fs2 {
		fs.Layers = append(fs.Layers, d.String())
	}

	result := types.ImageInspect{
		ID:           ima.Name(),
		RepoTags:     []string{ima.Name()},
		RepoDigests:  []string{ima.Target().Digest.String()},
		Architecture: spec.Architecture,
		Variant:      spec.Variant,
		Os:           spec.OS,
		OsVersion:    spec.OSVersion,
		Size:         ima.Target().Size,
		VirtualSize:  ima.Target().Size,
		GraphDriver:  types.GraphDriverData{},
		RootFS:       fs,
	}
	return result, nil
}

func (s *Driver) ListImages(ctx context.Context) ([]imagesecModel.ImageSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, consts.ContainerdRequestTimeout*time.Second)
	defer cancel()
	list, err := s.ContainerdCli.NamespaceService().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("get nsList failed.%v", err)
	}
	all := make([]imagesecModel.ImageSummary, 0)
	for _, ns := range list {
		nsCtx := namespaces.WithNamespace(ctx, ns)
		images, err := s.ContainerdCli.ListImages(nsCtx)
		if err != nil {
			logging.Get().Err(err).Str("namespace", ns).Msg("ListImages")
			continue
		}
		for _, ima := range images {
			all = append(all, imagesecModel.ImageSummary{
				Namespace:   ns,
				ID:          ima.Name(),
				RepoDigests: []string{ima.Target().Digest.String()},
				RepoTags:    []string{ima.Name()},
			})
		}
	}
	return all, nil
}

func (s *Driver) Type() string {
	return consts.ContainerdRuntime
}

func (s *Driver) ImageLayers(ctx context.Context, ns, imageID string) ([]image.HistoryResponseItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), consts.ContainerdRequestTimeout*time.Second)
	defer cancel()
	nsCtx := namespaces.WithNamespace(ctx, ns)
	ima, err := s.ContainerdCli.GetImage(nsCtx, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to get image , %v", err)
	}
	configDesc, err := ima.Config(nsCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image config, %v", err)
	}
	p, err := content.ReadBlob(nsCtx, ima.ContentStore(), configDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to get read image blob, %v", err)
	}
	var config ocispec.Image
	if err := json.Unmarshal(p, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal image config, %v", err)
	}
	history := make([]image.HistoryResponseItem, 0)
	for _, his := range config.History {
		h := image.HistoryResponseItem{
			Comment:   his.Comment,
			Created:   his.Created.Unix(),
			CreatedBy: his.CreatedBy,
		}
		history = append(history, h)
	}
	return history, nil
}

// func NewDriver(config cri.RuntimeConfig) (cri.Runtime, error) {
// 	var d Driver
// 	byt, err := json.Marshal(config.Options)
// 	if err != nil {
// 		logging.Get().
// 			Err(err).
// 			Interface("options", config.Options).
// 			Msg("runtime containerd marshal config failed")
// 		return nil, err
// 	}
// 	conf := DriverConfig{}
// 	if err := json.Unmarshal(byt, &conf); err != nil {
// 		logging.Get().
// 			Err(err).
// 			Bytes("config", byt).
// 			Msg("runtime containerd Unmarshal config failed")
// 		return nil, err
// 	}
// 	d.Config = conf
// 	if d.Config.Endpoint != "" {
// 		_ = os.Setenv("CONTAINERD_HOST", d.Config.Endpoint)
// 	}
// 	uri := GetContainerdAddr()
// 	// containerd client
// 	containerdCli, err := containerd.New(strings.TrimPrefix(uri, "unix://"), containerd.WithTimeout(5*time.Second))
// 	if err != nil {
// 		logging.Get().
// 			Err(err).
// 			Msg("create containerd client failed")
// 		return nil, err
// 	}
//
// 	d.ContainerdCli = containerdCli
//
// 	logging.Get().Info().Msg("New containerd Driver success")
// 	return &d, nil
// }

func NewDriver(config DriverConfig) (*Driver, error) {
	d := &Driver{
		ContainerdCli: nil,
		Config:        config,
	}

	if d.Config.Endpoint != "" {
		_ = os.Setenv("CONTAINERD_HOST", d.Config.Endpoint)
	}
	uri := GetContainerdAddr()
	containerdCli, err := containerd.New(uri, containerd.WithTimeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	d.ContainerdCli = containerdCli
	return d, nil
}

func GetContainerdAddr() string {
	uri := os.Getenv(consts.ENVContainerdSocketAddr)
	if len(uri) == 0 {
		uri = consts.DefaultContainerdSocket
	}
	uri = strings.TrimPrefix(uri, "unix://")
	return uri
}

type Schema struct {
	MediaType     string `json:"mediaType"`
	SchemaVersion int    `json:"schemaVersion"`
	ImageDigest   string `json:"imageDigest"`

	// Manifests 有值:"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json"
	Manifests []struct {
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
		Platform  struct {
			Architecture string `json:"architecture"`
			Os           string `json:"os"`
			Variant      string `json:"variant,omitempty"`
		} `json:"platform"`
		Size int `json:"size"`
	} `json:"manifests"`

	// Config,Layers有值："mediaType": "application/vnd.docker.distribution.manifest.v2+json"
	Config struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}

// func init() {
// 	err := cri.Register("containerd", NewDriver)
// 	if err != nil {
// 		log.Err(err).Msg("register docker driver failed")
// 		return
// 	}
// }

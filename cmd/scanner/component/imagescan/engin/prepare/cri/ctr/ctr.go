package ctr

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/namespaces"
	json "github.com/json-iterator/go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gitlab.com/security-rd/go-pkg/logging"

	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type DriverConfig struct {
	Endpoint string `json:"endpoint"`
}

type Driver struct {
	CriCli *containerd.Client
}

func NewDriver() (*Driver, error) {
	var d Driver

	uri := GetContainerdAddr()
	// containerd client
	containerdCli, err := containerd.New(strings.TrimPrefix(uri, "unix://"), containerd.WithTimeout(5*time.Second))
	if err != nil {
		logging.Get().
			Err(err).
			Msg("create containerd client failed")
		return nil, err
	}

	d.CriCli = containerdCli
	logging.Get().Info().Msg("New containerd Driver success")
	return &d, nil
}

func GetContainerdAddr() string {
	uri := os.Getenv("CONTAINERD_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/containerd/containerd.sock"
	}
	return uri
}

// 收集
func (s *Driver) Collect(ctx context.Context, im imagesecModel.Image) ([]imagesec.ImageLayer, error) {
	lys := make([]imagesec.ImageLayer, 0)
	imageName := im.GetImageName()
	nsCtx := namespaces.WithNamespace(context.Background(), im.Namespace)
	schema, err := s.GetImageSchema(ctx, im.Namespace, imageName)
	if err != nil {
		return lys, err
	}
	cs := s.CriCli.ContentStore()

	for i := range schema.Layers {
		ly := schema.Layers[i].Digest
		ra, err := cs.ReaderAt(nsCtx, ocispec.Descriptor{Digest: digest.Digest(ly)})
		if err != nil {
			logging.Get().Err(err).Str("image", imageName).Str("digest", schema.ImageDigest).Msg("ReaderAt")
			continue
		}
		fn, err := s.SaveImageTarFile(ctx, ra, schema.ImageDigest)
		if err != nil {
			logging.Get().Err(err).Str("image", imageName).Str("digest", schema.ImageDigest).Msg("SaveImageTarFile")
			continue
		}
		cdir, err := s.ExtractTar(ctx, fn, schema.ImageDigest)
		if err != nil {
			logging.Get().Err(err).Str("image", imageName).Str("digest", schema.ImageDigest).Msg("extractTarUseTar")
			continue
		}

		lys = append(lys, imagesec.ImageLayer{
			Digest:        ly,
			LayerFilePath: cdir,
			PreFix:        cdir,
		})
	}
	// 改成从lowDir到upperDir
	ans := make([]imagesec.ImageLayer, 0)
	for i := len(lys) - 1; i >= 0; i-- {
		ans = append(ans, lys[i])
	}

	return ans, nil
}

func (s *Driver) GetImageSchema(ctx context.Context, ns string, imaRef string) (Schema, error) {
	// imaRef：镜像全称
	var schema Schema
	nsCtx := namespaces.WithNamespace(context.Background(), ns)
	ima, err := s.CriCli.GetImage(nsCtx, imaRef)
	if err != nil {
		return schema, fmt.Errorf("failed to get ima , %v", err)
	}

	digestStr := ima.Target().Digest.String()
	if digestStr == "" {
		return schema, fmt.Errorf("not get image digest")
	}
	schema.ImageDigest = digestStr

	cs := s.CriCli.ContentStore()
	ra, err := cs.ReaderAt(nsCtx, ocispec.Descriptor{Digest: ima.Target().Digest})
	if err != nil {
		return schema, err
	}
	dataBytes, err := io.ReadAll(content.NewReader(ra))
	defer func() { _ = ra.Close() }()

	err = json.Unmarshal(dataBytes, &schema)
	if err != nil {
		return schema, fmt.Errorf("unmarshal schema1 faild. %v", err)
	}
	if len(schema.Layers) > 0 {
		return schema, nil
	}
	//  获取指定os的镜像digest
	var targetDigest string
	for _, manifest := range schema.Manifests {
		if manifest.Platform.Os == runtime.GOOS && manifest.Platform.Architecture == runtime.GOARCH {
			targetDigest = manifest.Digest
			break
		}
	}
	if targetDigest == "" {
		return schema, fmt.Errorf("not get image digetst")
	}
	ra, err = cs.ReaderAt(nsCtx, ocispec.Descriptor{Digest: digest.Digest(targetDigest)})
	if err != nil {
		return schema, fmt.Errorf("read manifest2 faild. %v", err)
	}
	dataBytes, err = io.ReadAll(content.NewReader(ra))
	if err != nil {
		return schema, err
	}
	err = json.Unmarshal(dataBytes, &schema)
	if err != nil {
		return schema, fmt.Errorf("unmarshal schema2 faild. %v", err)
	}
	return schema, nil
}

func (s *Driver) SaveImageTarFile(ctx context.Context, ra content.ReaderAt, di string) (string, error) {
	di = scannerUtils.GetSimDigest(di)
	temp, err := os.CreateTemp("", fmt.Sprintf("%s-*", di))
	if err != nil {
		return "", err
	}
	if _, err := io.CopyBuffer(temp, content.NewReader(ra), nil); err != nil {
		return "", err
	}
	if err := temp.Sync(); err != nil {
		return "", err
	}

	return temp.Name(), nil
}

func (s *Driver) ExtractTar(ctx context.Context, tarFile, dit string) (string, error) {
	defer func() {
		if err := os.RemoveAll(tarFile); err != nil {
			logging.Get().Err(err).Str("file", tarFile).Msg("containerd delete tar file")
		}
	}()

	temp, err := os.MkdirTemp("", fmt.Sprintf("%s-*", scannerUtils.GetSimDigest(dit)))
	if err != nil {
		return "", err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Minute)

	defer cancelFunc()
	cmd := exec.CommandContext(ctx, "tar", "-xf", tarFile, "-C", temp)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(temp)
		logging.Get().Err(err).Str("tarFile", tarFile).Msg("extractTarUseTar")
		return "", err
	}
	return temp, nil
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

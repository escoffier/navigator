package scanjob

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/pkg/errors"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/docker"
	image_cache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type JobPullImage struct {
	config types.Config
}

// 这还是原来的代码，这代码
func (p *JobPullImage) Run(ctx context.Context) (Artifact, error) {
	logging.Get().Debug().Str("module", "imagescan").Msg("pull image start")

	r := make(map[string]interface{})
	client, err := image_cache.NewLocalLayerManageClientT("/manifest")
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("new manifest client error")
		return nil, err
	}

	client1, err := image_cache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("new layer client error")
		return nil, err
	}

	manifestTmp, err := client.GetManifest(p.config.Username, p.config.Password, p.config.URL, p.config.RepoName, p.config.Tag, true)
	manifesv2 := schema2.DeserializedManifest{}
	manifesv1 := schema1.SignedManifest{}
	errV2 := manifesv2.UnmarshalJSON([]byte(manifestTmp))
	errV1 := manifesv1.UnmarshalJSON([]byte(manifestTmp))
	if errV2 != nil && errV1 != nil {
		return nil, fmt.Errorf("get manifest v1 and v2 error :%v,%v", errV1, errV2)
	}
	if errV1 != nil || errV2 != nil {
		// 说明是用的v1版本的manifest
		logging.Get().Err(err).Str("module", "imagescan").Msg("docker client GetManifest")
		logging.Get().Info().Str("module", "imagescan").Msg("try docker pull to GetManifest")

		imageName := fmt.Sprintf("%s/%s:%s", getLib(p.config.URL), p.config.RepoName, p.config.Tag)

		inspectInfo, err := getInspectInfo(p.config.URL, p.config.Username, p.config.Password, imageName)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("docker client not get manifest,and docker pull not get manifest")
			return nil, errors.WithMessage(err, "docker client not get manifest,and docker pull not get manifest")
		}
		bts, err := json.Marshal(inspectInfo.Config)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("Marshal inspectInfo.Config")
			return nil, err
		}
		r["imageName"] = imageName
		r["docker"] = 1
		r["digest"] = inspectInfo.Digest
		r["layers"] = inspectInfo.RootFS.Layers
		r["configJson"] = string(bts)
	} else {
		uniqueLayers := make(map[string]bool)
		layers := make([]string, 0)
		layersFilePath := make([]string, 0)
		manifest := schema2.DeserializedManifest{}
		err = manifest.UnmarshalJSON([]byte(manifestTmp))
		if err == nil {
			// 说明是V2版本
			layers = append(layers, manifest.Config.Digest.String())
			for _, layer := range manifest.Manifest.Layers {
				layerDigest := layer.Digest.String()
				if _, ok := uniqueLayers[layerDigest]; ok {
					continue
				}
				uniqueLayers[layerDigest] = true
				layers = append(layers, layerDigest)
			}
			imageDigest, err := docker.ManifestV2Digest(&manifest)
			if err == nil {
				r["digest"] = imageDigest
			}
		} else {
			// 说明是V1版本
			logging.Get().Err(err).Str("module", "imagescan").Msg("unmarshal v2 manifest error ,try unmarshal v1")

			maniFestV1 := new(model.ManifestV1)
			if err := json.Unmarshal([]byte(manifestTmp), maniFestV1); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("unmarshal v1 manifest ")
				// 不直接返回，后面直接用docker pull的方式再次验证
			}

			for _, his := range maniFestV1.History {
				for _, v := range his {
					hv1 := new(model.HistoryV1)
					if err := json.Unmarshal([]byte(v), hv1); err != nil {
						logging.Get().Debug().Str("module", "imagescan").Msg(fmt.Sprintf("Unmarshal ManifestV1.HistoryV1 error:%s", err.Error()))
						continue
					}
					ly := "sha256:" + hv1.LayerDigest
					if _, ok := uniqueLayers[ly]; ok {
						continue
					}
					uniqueLayers[ly] = true
					layers = append(layers, ly)
				}
			}
		}

		var layerPulled []string
		fixedPath := filepath.Join(image_cache.FileServerCache, image_cache.FileServerRootDir, image_cache.DataDir)
		for layer := range layers {
			layersFilePath = append(layersFilePath, filepath.Join(fixedPath, layers[layer]))
			_, _, err := client1.GetLayer(p.config.Username, p.config.Password, p.config.URL, p.config.RepoName, layers[layer], true)
			layerPulled = append(layerPulled, layers[layer])
			if err != nil {
				r["pullFailed"] = true
				r["layerPulled"] = layerPulled
				logging.Get().Err(err).Str("module", "imagescan").Msg("get layer failed")
				return r, fmt.Errorf("get layer failed %v", err)
			}
		}

		configJSON, err := os.ReadFile(filepath.Join(layersFilePath[0], "layer.tar"))
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msgf("Get config json err in pull image")
			return nil, err
		}
		r["layers"] = layers
		r["configJson"] = string(configJSON)
		r["layersFilePath"] = layersFilePath
	}
	// return image http url and layers local path
	// r["imageCacheUrl"] = "192.168.134.26:80/fff/alltest:latest"
	logging.Get().Info().Str("module", "imagescan").Msgf("dockerImage is %v:", p.config.URL+"/"+p.config.RepoName+":"+p.config.Tag)
	r["dockerImage"] = fmt.Sprintf("%s/%s:%s", getLib(p.config.URL), p.config.RepoName, p.config.Tag)
	r["imageName"] = fmt.Sprintf("%s/%s:%s", getLib(p.config.URL), p.config.RepoName, p.config.Tag)
	r["pullImageJob"] = p.config
	r["repoName"] = p.config.RepoName
	r["tag"] = p.config.Tag
	r["url"] = p.config.URL

	r["imageCacheUrl"] = image_cache.GenerateImageCacheURL(p.config.RepoName, p.config.Tag)
	logging.Get().Info().Str("module", "imagescan").Msg("pull image end")

	return r, nil
}

func NewPullImageJob(config types.Config) *JobPullImage {
	p := &JobPullImage{}

	p.config.CacheServerURL = config.CacheServerURL
	p.config.RepoName = config.RepoName
	p.config.Tag = config.Tag
	p.config.URL = config.URL
	p.config.Username = config.Username
	p.config.Password = config.Password

	return p
}

type Artifact map[string]interface{}

package pullimage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/docker"
	image_cache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	JobName = "pull-image"
)

type Config struct {
	CacheServerURL string // image cache server url
	RepoName       string // image name,eg: library/nginx
	Tag            string // tag,eg: latest
	URL            string // registry url
	ImageID        int64
	Username       string
	Password       string
	Secure         bool
}

type Job struct {
	config Config
}

// type PullImageResult struct {
//	ImageCacheUrl  string
//	LayerFilesPath map[string]string
// }

func (p *Job) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	logging.GetLogger().Debug().Msg("pull image start")

	r := make(map[string]interface{})
	client, err := image_cache.NewLocalLayerManageClientT("/manifest")
	if err != nil {
		logging.GetLogger().Err(err).Msg("new manifest client error")
		return nil, err
	}

	client1, err := image_cache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		logging.GetLogger().Err(err).Msg("new layer client error")
		return nil, err
	}

	manifestTmp, err := client.GetManifest(p.config.Username, p.config.Password, p.config.URL, p.config.RepoName, p.config.Tag, true)
	manifesv2 := schema2.DeserializedManifest{}
	manifesv1 := schema1.SignedManifest{}
	errV2 := manifesv2.UnmarshalJSON([]byte(manifestTmp))
	errV1 := manifesv1.UnmarshalJSON([]byte(manifestTmp))
	if errV2 != nil && errV1 != nil {
		return nil, fmt.Errorf("get manifest v1 and v2 error :%v", err)
	}
	if err != nil || errV2 != nil {
		// 说明是用的v1版本的manifest
		logging.GetLogger().Err(err).Msg("docker client GetManifest")
		logging.GetLogger().Info().Msg("try docker pull to GetManifest")

		imageName := fmt.Sprintf("%s/%s:%s", getLib(p.config.URL), p.config.RepoName, p.config.Tag)

		inspectInfo, err := getInspectInfo(p.config.URL, p.config.Username, p.config.Password, imageName)
		if err != nil {
			logging.GetLogger().Err(err).Msg("docker client not get manifest,and docker pull not get manifest")
			return nil, errors.WithMessage(err, "docker client not get manifest,and docker pull not get manifest")
		}
		bts, err := json.Marshal(inspectInfo.Config)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Marshal inspectInfo.Config")
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
			logging.GetLogger().Err(err).Msg("unmarshal v2 manifest error ,try unmarshal v1")

			maniFestV1 := new(model.ManifestV1)
			if err := json.Unmarshal([]byte(manifestTmp), maniFestV1); err != nil {
				logging.GetLogger().Err(err).Msg("unmarshal v1 manifest ")
				// 不直接返回，后面直接用docker pull的方式再次验证
			}

			for _, his := range maniFestV1.History {
				for _, v := range his {
					hv1 := new(model.HistoryV1)
					if err := json.Unmarshal([]byte(v), hv1); err != nil {
						logging.GetLogger().Debug().Msg(fmt.Sprintf("Unmarshal ManifestV1.HistoryV1 error:%s", err.Error()))
						continue
					}
					ly := "sha256:" + hv1.LayerDegest
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
				logging.GetLogger().Err(err).Msg("get layer failed")
				return r, fmt.Errorf("get layer failed %v", err)
			}
		}

		configJSON, err := os.ReadFile(filepath.Join(layersFilePath[0], "layer.tar"))
		if err != nil {
			logging.GetLogger().Err(err).Msgf("Get config json err in pull image")
			return nil, err
		}
		r["layers"] = layers
		r["configJson"] = string(configJSON)
		r["layersFilePath"] = layersFilePath
	}
	// return image http url and layers local path
	// r["imageCacheUrl"] = "192.168.134.26:80/fff/alltest:latest"
	logging.GetLogger().Info().Msgf("dockerImage is %v:", p.config.URL+"/"+p.config.RepoName+":"+p.config.Tag)
	r["dockerImage"] = fmt.Sprintf("%s/%s:%s", getLib(p.config.URL), p.config.RepoName, p.config.Tag)
	r["pullImageJob"] = p.config
	r["repoName"] = p.config.RepoName
	r["tag"] = p.config.Tag
	r["url"] = p.config.URL

	r["imageCacheUrl"] = image_cache.GenerateImageCacheURL(p.config.RepoName, p.config.Tag)
	// r["layers"] = layers
	// r["layersFilePath"] = layersFilePath
	// r["configJson"] = string(configJSON)
	logging.GetLogger().Info().Msg("pull image end")

	return r, nil
}

func init() {
	err := jobs.Register(JobName, newJob)
	if err != nil {
		logging.GetLogger().Err(err).Str("jobName", JobName).Msg("int job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	p := &Job{}

	p.config.CacheServerURL = config.Info.CacheServerURL
	p.config.RepoName = config.Info.SubTask.Image.RepoName
	p.config.Tag = config.Info.SubTask.Image.Tag
	p.config.URL = config.Info.SubTask.Registry.Host
	p.config.ImageID = config.Info.SubTask.Image.ID
	p.config.Username = config.Info.SubTask.Registry.Username
	p.config.Password = config.Info.SubTask.Registry.Password
	p.config.Secure = config.Info.SubTask.Registry.Secure

	return p, nil
}

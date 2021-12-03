package pull_image

import (
	"context"
	"os"
	"path/filepath"

	"github.com/docker/distribution/manifest/schema2"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	image_cache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	PullImageJobName = "pull-image"
)

type Config struct {
	CacheServerUrl string // image cache server url
	RepoName       string // image name,eg: library/nginx
	Tag            string // tag,eg: latest
	Url            string // registry url
	Username       string
	Password       string
	Secure         bool
}

type PullImageJob struct {
	config Config
}

// type PullImageResult struct {
//	ImageCacheUrl  string
//	LayerFilesPath map[string]string
// }

func (p *PullImageJob) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	logging.GetLogger().Debug().Msg("pull image start")

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

	manifestTmp, err := client.GetManifest(p.config.Username, p.config.Password, p.config.Url, p.config.RepoName, p.config.Tag, true)
	if err != nil {
		logging.GetLogger().Err(err).Msg("new layer client error")
		return nil, err
	}
	uniqueLayers := make(map[string]bool)
	layers := make([]string, 0)
	layersFilePath := make([]string, 0)
	manifest := schema2.DeserializedManifest{}
	err = manifest.UnmarshalJSON([]byte(manifestTmp))
	if err != nil {
		logging.GetLogger().Err(err).Msg("unmarshall manifest error")
		return nil, err
	}
	layers = append(layers, manifest.Config.Digest.String())

	for _, layer := range manifest.Manifest.Layers {
		layerDigest := layer.Digest.String()
		if _, ok := uniqueLayers[layerDigest]; ok {
			// return []string{}, fmt.Errorf("Found duplicate layer digest in V2 manifest")
			continue
		}
		uniqueLayers[layerDigest] = true
		layers = append(layers, layerDigest)
	}

	fixedPath := filepath.Join(image_cache.FileServerCache, image_cache.FileServerRootDir, image_cache.DataDir)
	for layer := range layers {
		layersFilePath = append(layersFilePath, filepath.Join(fixedPath, layers[layer]))
		_, _, err := client1.GetLayer(p.config.Username, p.config.Password, p.config.Url, p.config.RepoName, layers[layer], true)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get layer failed")
			return nil, err
		}
	}

	configJson, err := os.ReadFile(filepath.Join(layersFilePath[0], "layer.tar"))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Get config json err in pull image")
		return nil, err
	}
	// return image http url and layers local path
	r := make(map[string]interface{})
	// r["imageCacheUrl"] = "192.168.134.26:80/fff/alltest:latest"
	r["pullImageJob"] = p.config
	r["repoName"] = p.config.RepoName
	r["tag"] = p.config.Tag
	r["url"] = p.config.Url
	r["imageCacheUrl"] = image_cache.GenerateImageCacheUrl(p.config.RepoName, p.config.Tag)
	r["layers"] = layers
	r["layersFilePath"] = layersFilePath
	r["configJson"] = string(configJson)
	logging.GetLogger().Info().Msg("pull image end")

	return r, nil
}

func init() {
	err := jobs.Register(PullImageJobName, newJob)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("jobName", PullImageJobName).Msg("int job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	p := &PullImageJob{}

	p.config.CacheServerUrl = config.Info.CacheServerUrl
	p.config.RepoName = config.Info.SubTask.Image.RepoName
	p.config.Tag = config.Info.SubTask.Image.Tag
	p.config.Url = config.Info.SubTask.Registry.Host
	p.config.Username = config.Info.SubTask.Registry.Username
	p.config.Password = config.Info.SubTask.Registry.Password
	p.config.Secure = config.Info.SubTask.Registry.Secure

	return p, nil
}

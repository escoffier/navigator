package mock_pull_image

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	MockPullImageJobName = "mock-pull-image"
	testImageUrl         = "nginx:1.20"
)

type Config struct {
	cacheServerUrl string // image cache server url
	repoName       string // image name,eg: library/nginx
	tag            string // tag,eg: latest
	url            string // registry url
	username       string
	password       string
	secure         bool
}

type MockPullImageJob struct {
	config Config
}

func (p *MockPullImageJob) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	// return image http url and layers local path
	l := make(map[string]string)
	r := make(map[string]interface{})
	//r["imageCacheUrl"] = testImageUrl
	r["imageCacheUrl"] = fmt.Sprintf("%s:%s", p.config.repoName, p.config.tag)
	r["layersFilePath"] = l
	return r, nil
}

func init() {
	err := jobs.Register(MockPullImageJobName, newJob)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("jobName", MockPullImageJobName).Msg("int job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	p := &MockPullImageJob{}

	p.config.cacheServerUrl = config.Info.CacheServerURL
	p.config.repoName = config.Info.SubTask.Image.RepoName
	p.config.tag = config.Info.SubTask.Image.Tag
	p.config.url = config.Info.SubTask.Registry.Host
	p.config.username = config.Info.SubTask.Registry.Username
	p.config.password = config.Info.SubTask.Registry.Password
	p.config.secure = config.Info.SubTask.Registry.Secure

	return p, nil
}

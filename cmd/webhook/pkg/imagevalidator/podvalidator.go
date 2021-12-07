package imagevalidator

import (
	"context"
	flag "github.com/spf13/pflag"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
)

var ApiPath = "/api/v1/imagereject/online_moniter"
var imageValidateHost = ""

const configFile = "image-validator.yaml"

type ImageValidator struct {
	config *Config
}

type Config struct {
	ImageValidateHost string   `yaml:"imageValidateHost"`
	IgnoredNameSpaces []string `yaml:"ignoredNameSpaces"`
	ValidatorUrl      string
}

func (v *ImageValidator) Init(webHookConfig *processors.WebHookConfig) error {
	logging.GetLogger().Info().Msg("init ImageValidator")
	//v.ValidatorUrl = "test/123"
	path := processors.GetConfigFullPath(configFile)
	config, err := loadConfig(path)
	if err != nil {
		return err
	}
	v.config = config
	return nil
}

func (v *ImageValidator) PreValidate(_ context.Context, _ *v1.Pod, parameters *processors.ValidatingParameters) bool {
	for _, ns := range v.config.IgnoredNameSpaces {
		if parameters.Namespace == ns {
			logging.GetLogger().Info().Msgf("ignored validating for resource %s in namespace %s", parameters.Kind, ns)
			return false
		}
	}
	return true
}

func (v *ImageValidator) Validate(_ context.Context, pod *v1.Pod, params *processors.ValidatingParameters) error {
	return v.ValidateImage(params, pod)
}

func (v *ImageValidator) Name() string {
	return "ImageValidator"
}

func loadConfig(path string) (*Config, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read config file failed")
		return nil, err
	}

	config := Config{}
	err = yaml.Unmarshal(b, &config)
	if err != nil {
		return nil, err
	}
	config.ValidatorUrl = "http://" + config.ImageValidateHost + ApiPath
	return &config, nil
}

func Register() {
	imageValidator := ImageValidator{}
	processors.Registry(imageValidator.Name(), imageValidator)
}

func init() {
	flag.StringVar(&imageValidateHost, "ImageValidateHost", "127.0.0.1:80", "The URL of tls image checking server")
}

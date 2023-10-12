package imagetrust

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
)

const validatorConfigFile = "image-trust-validator.yaml"

type Validator struct {
	client            *http.Client
	digestUrl         string
	IgnoredNameSpaces []string
}

type RejectOnlineMonitorImage struct {
	Image    string `json:"image"`
	FromType string `json:"type"`
	Digest   string `json:"digest"`
	//CustomKV []KVHash `json:"custom_KV"` //自定义kv
}

type ImageValidatorReq struct {
	Images        []RejectOnlineMonitorImage
	NotifyContext model.NotifyContext `json:"notify_context"`
}
type Result struct {
	ApiVersion string `json:"apiVersion"`
	Data       Data   `json:"data"`
}

type Data struct {
	Item  Item   `json:"item"`
	Items []Item `json:"items"`
}

type Item struct {
	Flag bool `json:"flag"`
}

type ValidatorConfig struct {
	ImageTrustUrl     string   `yaml:"image_trust_url"`
	IgnoredNameSpaces []string `yaml:"ignored_name_spaces"`
}

func (v *Validator) Validate(ctx context.Context, digests *PodImageDigest, params *processors.ValidatingParameters) error {
	validation := &ImageValidatorReq{
		NotifyContext: model.NotifyContext{
			PodUID:    "",
			PodName:   "",
			Namespace: params.Namespace,
			Cluster:   params.ClusterKey,
			CustomKV: []model.KVHashs{
				{KVHash: model.KVHash{
					EN: model.KeyValue{
						Key:   "ResourceKind",
						Value: params.ResourceKind,
					},
					ZH: model.KeyValue{
						Key:   "ResourceKind",
						Value: params.ResourceKind,
					},
				}},
				{KVHash: model.KVHash{
					EN: model.KeyValue{
						Key:   "ResourceKind",
						Value: params.ResourceName,
					},
					ZH: model.KeyValue{
						Key:   "ResourceKind",
						Value: params.ResourceName,
					},
				}},
			},
		},
	}

	for _, image := range digests.InitContainerImages {
		buildValidation(validation, image)
	}

	for _, image := range digests.ContainerImages {
		buildValidation(validation, image)
	}
	if len(validation.Images) == 0 {
		return nil
	}

	data, err := json.Marshal(validation.Images)
	if err != nil {
		logging.Get().Err(err).Msg("marshal json err")
		return nil
	}

	logging.Get().Info().Msgf("validation data: %s", string(data))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.digestUrl, bytes.NewReader(data))
	if err != nil {
		logging.Get().Err(err).Msg("create request failed")
		return nil
	}

	var validationResp Result
	err = util.HTTPRequest(ctx, v.client, req, func(resp *http.Response, err error) error {
		if err != nil {
			return err
		}

		if resp.Body == nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		logging.Get().Debug().Msgf("resp %s", string(body))
		err = json.Unmarshal(body, &validationResp)
		if err != nil {
			logging.Get().Err(err).Msgf("validation resp err")
			return err
		}
		return nil
	}, retry.Attempts(3))
	if err != nil {
		logging.Get().Err(err).Msg("http request failed")
		return nil
	}

	if !validationResp.Data.Item.Flag {
		return errors.New("image is untrusted")
	}

	return nil
}

func buildValidation(v *ImageValidatorReq, image ImageDigest) {
	var digest, imageTag string
	digest = getDigest(image.Digest)
	if digest != "" {
		imageMap, ok := GetImageDigestMap()
		if ok {
			imageTag = imageMap.get(digest)
		}
	}
	if imageTag == "" {
		imageTag = image.Image
	}
	v.Images = append(v.Images, RejectOnlineMonitorImage{
		Image:    imageTag,
		FromType: "k8s_deployment",
		Digest:   digest,
	})
}

func (v *Validator) PreValidate(_ context.Context, _ *corev1.Pod, parameters *processors.ValidatingParameters) bool {
	for _, ns := range v.IgnoredNameSpaces {
		if parameters.Namespace == ns {
			logging.Get().Info().Msgf("ignored mutating for resource %s in namespace %s", parameters.Kind, ns)
			return false
		}
	}
	return true
}

func (v *Validator) Name() string {
	return "ImageTrustValidator"
}

func (v *Validator) Init(_ *processors.WebHookConfig) error {
	v.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	path := processors.GetConfigFullPath(validatorConfigFile)
	validatorConfig, err := loadValidatorConfig(path)
	if err != nil {
		logging.Get().Err(err).Msg("load config err")
		return err
	}

	digestUrl, err := url.Parse(validatorConfig.ImageTrustUrl)
	if err != nil {
		return err
	}

	v.digestUrl = digestUrl.String()
	v.IgnoredNameSpaces = append(v.IgnoredNameSpaces, validatorConfig.IgnoredNameSpaces...)
	return nil
}

func loadValidatorConfig(path string) (*ValidatorConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		logging.Get().Err(err).Msg("read config file failed")
		return nil, err
	}

	config := ValidatorConfig{}
	err = yaml.Unmarshal(b, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func getDigest(image string) string {
	s := strings.SplitN(image, "@", 2)
	if s == nil || len(s) != 2 {
		return ""
	}
	return s[1]
}

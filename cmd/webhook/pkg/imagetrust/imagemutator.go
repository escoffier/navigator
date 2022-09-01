package imagetrust

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
)

const configFile = "image-trust-mutator.yaml"

var checkImageRegistryUrl = ""

type Mutator struct {
	client            *http.Client
	digestUrl         string
	IgnoredNameSpaces []string
	secretInformer    map[string]*coreinformers.SecretInformer
}

type ImageTagReq struct {
	InitContainerImages []string `json:"init_container_images"`
	ContainerImages     []string `json:"container_images"`
}

type ImageDigest struct {
	InitContainerImages []string `json:"init_container_images"`
	ContainerImages     []string `json:"container_images"`
}

type ImageDigestResp ImageTagReq

type MutatorConfig struct {
	IgnoredNameSpaces     []string `yaml:"ignored_name_spaces"`
	ImageRegistryCheckUrl string   `yaml:"image_registry_check_url"`
}

type ImageRegistry struct {
	Url string `json:"url"`
}

func (m *Mutator) Name() string {
	return "ImageTrustMutator"
}

func (m *Mutator) Init(webHookConfig *processors.WebHookConfig) error {
	if webHookConfig.RDB == nil {
		return errors.New("invalid rdb")
	}
	m.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	path := processors.GetConfigFullPath(configFile)
	config, err := loadMutatorConfig(path)
	if err != nil {
		logging.GetLogger().Err(err).Msg("load config err")
		return err
	}

	checkUrl, err := url.Parse(config.ImageRegistryCheckUrl)
	if err != nil {
		return err
	}

	checkImageRegistryUrl = checkUrl.String()
	m.IgnoredNameSpaces = append(m.IgnoredNameSpaces, config.IgnoredNameSpaces...)
	InitImageDigestMap()
	return nil
}

func (m *Mutator) Mutate(ctx context.Context, parameters *processors.MutatorParameters, pod *corev1.Pod) []*processors.Patch {

	digests := &ImageDigest{}
	var kubeSecretNames []string
	for _, secs := range pod.Spec.ImagePullSecrets {
		kubeSecretNames = append(kubeSecretNames, secs.Name)
	}

	for index := range pod.Spec.InitContainers {
		digests.InitContainerImages = append(digests.InitContainerImages,
			m.buildDigestImage(ctx, parameters, &pod.Spec.InitContainers[index], kubeSecretNames))
	}

	for index := range pod.Spec.Containers {
		digests.ContainerImages = append(digests.ContainerImages,
			m.buildDigestImage(ctx, parameters, &pod.Spec.Containers[index], kubeSecretNames))
	}

	return patchImageDigest(digests)
}

// buildDigestImage replace image name with image digest
func (m *Mutator) buildDigestImage(ctx context.Context, parameters *processors.MutatorParameters, container *corev1.Container, kubeSecretNames []string) string {
	originImage := container.Image
	result := checkRegistryUrl(ctx, originImage)
	if !result {
		logging.GetLogger().Info().Msgf("skip check for image: %s", originImage)
		return ""
	}

	if strings.Contains(originImage, "@sha256") || container.ImagePullPolicy != "Always" {
		return ""
	}
	secret := m.getSecrets(parameters.ClusterKey, parameters.Namespace, originImage, kubeSecretNames)
	digest := getImageDigestFromHarbor(ctx, originImage, secret)
	if digest != "" {
		imgMap, ok := GetImageDigestMap()
		if ok {
			imgMap.add(digest, originImage)
		}
		return replaceTagWithDigest(originImage, digest)
	}
	logging.GetLogger().Warn().Msgf("can't get digest of [%s]", originImage)
	return ""
}

func (m *Mutator) PreMutate(_ context.Context, _ *corev1.Pod, parameters *processors.MutatorParameters) bool {
	for _, ns := range m.IgnoredNameSpaces {
		if parameters.Namespace == ns {
			logging.GetLogger().Info().Msgf("ingored mutating for resource %s in namespace %s", parameters.Kind, ns)
			return false
		}
	}
	return true
}

func patchImageDigest(imageDigest *ImageDigest) []*processors.Patch {
	patches := make([]*processors.Patch, 0)
	for i, digest := range imageDigest.InitContainerImages {
		if digest != "" {
			path := fmt.Sprintf("/spec/initContainers/%d/image", i)
			patches = append(patches, &processors.Patch{
				Op:    "replace",
				Path:  path,
				Value: imageDigest.InitContainerImages[i],
			})
		}
	}

	for i, digest := range imageDigest.ContainerImages {
		if digest != "" {
			path := fmt.Sprintf("/spec/containers/%d/image", i)
			patches = append(patches, &processors.Patch{
				Op:    "replace",
				Path:  path,
				Value: imageDigest.ContainerImages[i],
			})
		}
	}
	logPatches(patches)

	return patches
}

func logPatches(patches []*processors.Patch) {
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to marshal patches")
		return
	}
	logging.GetLogger().Info().Msg(string(patchData))
}

func getImageDigestFromHarbor(_ context.Context, image string, secret *utils.ImageRepoSecret) string {
	var digest string
	var err error

	if secret != nil {
		logging.GetLogger().Info().Msgf("image [%s] pulling secret %v", image, *secret)
		digest, err = utils.GetImageDigest(secret.User, secret.Password, true, image)
	} else {
		logging.GetLogger().Info().Msgf("image [%s] pulling secret is empty", image)
		digest, err = utils.GetImageDigest("", "", true, image)
	}

	if err != nil {
		logging.GetLogger().Warn().Err(err).Str("image", image).Msg("get digest of image from harbor error")
		return ""
	}
	return digest
}

func loadMutatorConfig(path string) (*MutatorConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read config file failed")
		return nil, err
	}

	config := MutatorConfig{}
	err = yaml.Unmarshal(b, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func (m *Mutator) getSecrets(clusterKey, namespace, image string, kubeSecrets []string) *utils.ImageRepoSecret {
	imageUrl, err := utils.GetImageUrl(image)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get %s url err", image)
		return nil
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		logging.GetLogger().Err(errors.New("cluster manager not ready")).Msg(image)
		return nil
	}
	for _, s := range kubeSecrets {
		client, ok := clusterManager.GetClient(clusterKey)
		if !ok {
			logging.GetLogger().Err(err).Msgf("get cluster client of %s err", clusterKey)
			return nil
		}
		secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), s, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get secret of %s err", s)
			return nil
		}
		data, ok := secret.Data[".dockerconfigjson"]
		if !ok {
			logging.GetLogger().Err(err).Msg("invalid secret")
			return nil
		}

		var dockerConfig utils.DockerConfigJSON
		err = json.Unmarshal(data, &dockerConfig)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("parse docker config err")
			return nil
		}
		logging.GetLogger().Info().Msgf("%+v", dockerConfig)

		for u, config := range dockerConfig.Auths {
			if u == imageUrl {
				return &utils.ImageRepoSecret{
					User:     config.Username,
					Password: config.Password,
				}
			}
		}
	}
	logging.GetLogger().Info().Msgf("not found secret for %s", image)
	return nil
}

func replaceTagWithDigest(image, digest string) string {
	s := strings.SplitN(image, ":", 2)
	if s == nil || len(s) == 1 {
		return image
	}

	return s[0] + "@" + digest
}

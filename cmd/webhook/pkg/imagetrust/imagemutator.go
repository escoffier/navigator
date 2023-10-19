package imagetrust

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const configFile = "image-trust-mutator.yaml"

var checkImageRegistryUrl string

type Mutator struct {
	client            *http.Client
	IgnoredNameSpaces []string
	kubeCli           *kubernetes.Clientset
	validator         *Validator
}

type ImageTagReq struct {
	InitContainerImages []string `json:"init_container_images"`
	ContainerImages     []string `json:"container_images"`
}

type ImageDigest struct {
	Image  string
	Digest string
}
type PodImageDigest struct {
	InitContainerImages []ImageDigest `json:"init_container_images"`
	ContainerImages     []ImageDigest `json:"container_images"`
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
		logging.Get().Warn().Err(err).Msg("load config err")
		return err
	}

	checkUrl, err := url.Parse(config.ImageRegistryCheckUrl)
	if err != nil {
		return err
	}

	checkImageRegistryUrl = checkUrl.String()
	m.IgnoredNameSpaces = append(m.IgnoredNameSpaces, config.IgnoredNameSpaces...)
	InitImageDigestMap()
	m.kubeCli = webHookConfig.KubeCli

	m.validator = &Validator{}
	m.validator.Init(nil)
	return nil
}

func (m *Mutator) Mutate(ctx context.Context, parameters *processors.MutatorParameters, pod *corev1.Pod) ([]*processors.Patch, error) {
	digests := &PodImageDigest{}
	var kubeSecretNames []string
	for _, secs := range pod.Spec.ImagePullSecrets {
		kubeSecretNames = append(kubeSecretNames, secs.Name)
	}

	for index := range pod.Spec.InitContainers {
		digests.InitContainerImages = append(digests.InitContainerImages,
			m.buildDigestImage(ctx, parameters, &pod.Spec.InitContainers[index], kubeSecretNames))
	}
	labelMap := make(map[string]string)
	for index := range pod.Spec.Containers {
		digestImage := m.buildDigestImage(ctx, parameters, &pod.Spec.Containers[index], kubeSecretNames)
		imagTag := getImageTag(pod.Spec.Containers[index].Image)
		labelMap[pod.Spec.Containers[index].Name] = imagTag
		digests.ContainerImages = append(digests.ContainerImages, digestImage)
	}
	patch := patchImageDigest(digests)
	err := m.validator.Validate(ctx, digests, &processors.ValidatingParameters{
		ClusterKey:   parameters.ClusterKey,
		Namespace:    parameters.Namespace,
		ResourceKind: parameters.ResourceKind,
		ResourceName: parameters.ResourceName,
	})
	if len(labelMap) > 0 {
		patch = append(patch, patchLabel(labelMap)...)
	}
	return patch, err
}

// buildDigestImage replace image name with image digest
func (m *Mutator) buildDigestImage(ctx context.Context, parameters *processors.MutatorParameters, container *corev1.Container, kubeSecretNames []string) ImageDigest {
	originImage := container.Image
	if strings.Contains(originImage, "@sha256") || container.ImagePullPolicy != "Always" {
		return ImageDigest{Image: originImage}
	}
	secret := m.getSecrets(parameters.ClusterKey, parameters.Namespace, originImage, kubeSecretNames)
	digest := getImageDigestFromHarbor(ctx, originImage, secret)
	if digest != "" {
		imgMap, ok := GetImageDigestMap()
		if ok {
			imgMap.add(digest, originImage)
		}
		return ImageDigest{Image: originImage, Digest: replaceTagWithDigest(originImage, digest)}
	}
	logging.Get().Warn().Msgf("can't get digest of [%s]", originImage)
	return ImageDigest{Image: originImage}
}

func (m *Mutator) PreMutate(_ context.Context, _ *corev1.Pod, parameters *processors.MutatorParameters) bool {
	for _, ns := range m.IgnoredNameSpaces {
		if parameters.Namespace == ns {
			logging.Get().Info().Msgf("ingored mutating for resource %s in namespace %s", parameters.Kind, ns)
			return false
		}
	}
	return true
}

func patchImageDigest(imageDigest *PodImageDigest) []*processors.Patch {
	patches := make([]*processors.Patch, 0)
	for i, digest := range imageDigest.InitContainerImages {
		if digest.Digest != "" {
			path := fmt.Sprintf("/spec/initContainers/%d/image", i)
			patches = append(patches, &processors.Patch{
				Op:    "replace",
				Path:  path,
				Value: imageDigest.InitContainerImages[i].Digest,
			})
		}
	}

	for i, digest := range imageDigest.ContainerImages {
		if digest.Digest != "" {
			path := fmt.Sprintf("/spec/containers/%d/image", i)
			patches = append(patches, &processors.Patch{
				Op:    "replace",
				Path:  path,
				Value: imageDigest.ContainerImages[i].Digest,
			})
		}
	}
	logPatches(patches)
	return patches
}

func patchLabel(labelMap map[string]string) []*processors.Patch {
	patches := make([]*processors.Patch, 0)
	for key, value := range labelMap {
		if value != "" {
			patches = append(patches, &processors.Patch{
				Op:    "add",
				Path:  "/metadata/labels/" + fmt.Sprintf("%s-image-tag", key),
				Value: value,
			})
		}
	}
	logPatches(patches)
	return patches
}

func logPatches(patches []*processors.Patch) {
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.Get().Warn().Err(err).Msg("failed to marshal patches")
		return
	}
	logging.Get().Info().Msgf("patch data: %s", string(patchData))
}

func getImageDigestFromHarbor(ctx context.Context, image string, secret *utils.ImageRepoSecret) string {
	var digest string
	var err error

	var user, password string
	if secret != nil {
		user = secret.User
		password = secret.Password
	} else {
		logging.Get().Info().Msgf("image [%s] pulling secret is empty", image)
	}

	digest, err = utils.GetImageDigest(ctx, user, password, true, image)

	if err != nil {
		logging.Get().Warn().Err(err).Str("image", image).Msg("get digest of image from harbor error")
		return ""
	}
	return digest
}

func loadMutatorConfig(path string) (*MutatorConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		logging.Get().Warn().Err(err).Msg("read config file failed")
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
		logging.Get().Warn().Err(err).Msgf("get %s url err", image)
		return nil
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		logging.Get().Warn().Err(errors.New("cluster manager not ready")).Msg(image)
		return nil
	}
	for _, s := range kubeSecrets {
		client, ok := clusterManager.GetClient(clusterKey)
		if !ok {
			logging.Get().Warn().Err(err).Msgf("get cluster client of %s err", clusterKey)
			return nil
		}
		secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), s, metav1.GetOptions{})
		if err != nil {
			logging.Get().Warn().Err(err).Msgf("get secret %s err", s)
			return nil
		}
		data, ok := secret.Data[".dockerconfigjson"]
		if !ok {
			logging.Get().Warn().Err(err).Msg("invalid secret")
			return nil
		}

		var dockerConfig utils.DockerConfigJSON
		err = json.Unmarshal(data, &dockerConfig)
		if err != nil {
			logging.Get().Warn().Err(err).Msgf("parse docker config err")
			return nil
		}
		logging.Get().Info().Msgf("%+v", dockerConfig)

		for u, config := range dockerConfig.Auths {
			if u == imageUrl {
				if config.Auth != "" {
					encoder := base64.StdEncoding
					data, err := encoder.DecodeString(config.Auth)
					if err != nil {
						logging.Get().Warn().Err(err).Msgf("decode docker auth: [%s] err", config.Auth)
						continue
					}
					auth := strings.SplitN(string(data), ":", 2)
					if len(auth) != 2 {
						logging.Get().Warn().Msgf("invalid docker auth %s", config.Auth)
						continue
					}
					return &utils.ImageRepoSecret{
						User:     auth[0],
						Password: auth[1],
					}
				} else {
					return &utils.ImageRepoSecret{
						User:     config.Username,
						Password: config.Password,
					}
				}
			}
		}
	}
	logging.Get().Info().Msgf("not found secret for %s", image)
	return nil
}

func replaceTagWithDigest(image, digest string) string {
	s := strings.SplitN(image, ":", 2)
	if s == nil || len(s) == 1 {
		return image
	}

	return s[0] + "@" + digest
}

func getImageTag(image string) string {
	if strings.Contains(image, "@sha256") {
		return ""
	}
	_, _, tag := util.ParseImage(image)
	return tag
}

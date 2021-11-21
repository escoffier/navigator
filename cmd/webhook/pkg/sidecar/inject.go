package inject

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"

	//"github.com/Masterminds/sprig/v3"
	"github.com/ghodss/yaml"
	sprig "github.com/go-task/slim-sprig"
	"gomodules.xyz/jsonpatch/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	//"github.com/gogo/protobuf/types"
	corev1 "k8s.io/api/core/v1"
)

const SidecarAnnotationStatusKey = "tensor-sidecar-inject/status"

type ProxyConfig struct {
	InterceptionMode   string   `json:"interception_mode"`
	NatsUrls           string   `json:"nats_urls"`
	NatsSubject        string   `json:"nats_subject"`
	NatsClusterId      string   `json:"nats_cluster_id"`
	IgnoredNameSpaces  []string `json:"ignored_name_spaces"`
	InitContainerImage string   `json:"init_container_image"`
	ContainerImage     string   `json:"container_image"`
	ImagePullSecrets   string   `json:"image_pull_secrets"`
	PgAddr             string   `json:"pg_addr"`
}

type SidecarTemplateData struct {
	ObjectMeta  *metav1.ObjectMeta
	Spec        corev1.PodSpec
	ProxyConfig *ProxyConfig
	ClusterKey  string
	OwnerName   string
	OwnerKind   string
}

type InjectionParameters struct {
	Template    string
	ProxyConfig *ProxyConfig
	OwnerName   string
	OwnerKind   string
}

func DefaultProxyConfig() *ProxyConfig {
	// TODO: include revision based on REVISION env
	// TODO: set default namespace based on POD_NAMESPACE env
	return &ProxyConfig{
		InterceptionMode: "REDIRECT",
		NatsUrls:         "nats://localhost:4222",
		NatsSubject:      "security-api",
	}
}

type Injector struct {
	params *InjectionParameters
	rdb    *rdbtools.GormWrapper
}

func (in *Injector) Name() string {
	return "SidecarInjector"
}

func (in *Injector) Init() error {
	var err error
	in.params, err = loadConfig()
	if err != nil {
		logging.GetLogger().Err(err).Msg("load config err")
		return err
	}

	postgresDB, err := rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
		db, err := gorm.Open(postgres.Open(in.params.ProxyConfig.PgAddr), &gorm.Config{Logger: logger.Discard.LogMode(logger.Silent)})
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
			return nil, err
		}
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.SetMaxOpenConns(30)
			sqlDB.SetMaxIdleConns(5)
			sqlDB.SetConnMaxLifetime(time.Hour)
		}
		return db, nil
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("Init postgre error")
		return err
	}
	in.rdb = postgresDB
	return nil
}

func (in *Injector) Mutate(ctx context.Context, parameters *processors.MutatorParameters, pod *corev1.Pod) []*processors.Patch {
	originalPodSpec, err := json.Marshal(pod)
	if err != nil {
		logging.GetLogger().Err(err).Msg("marshal pod to json")
		return nil
	}

	ownerName, ownerKind := in.getPodOwner(ctx, pod, parameters)
	data := SidecarTemplateData{
		ObjectMeta:  &pod.ObjectMeta,
		Spec:        pod.Spec,
		ProxyConfig: in.params.ProxyConfig,
		ClusterKey:  parameters.ClusterKey,
		OwnerKind:   ownerKind,
		OwnerName:   ownerName,
	}

	buf, err := parseTemplate(in.params.Template, data)
	if err != nil {
		logging.GetLogger().Warn().Msg("parse template err")
		return nil
	}

	templateJSON, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		logging.GetLogger().Err(err).Msg("yaml to json")
		return nil
	}

	newPod, err := applyOverlay(pod, templateJSON)
	if err != nil {
		logging.GetLogger().Err(err).Msg("apply overlay")
		return nil
	}

	patches := make([]*processors.Patch, 0)
	p, err := createPatch(newPod, originalPodSpec)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create pods path")
		return patches
	}
	for _, v := range p {
		patches = append(patches, &processors.Patch{
			Op:    v.Operation,
			Path:  v.Path,
			Value: v.Value,
		})
	}

	logPatches(patches)
	return patches
}

func (in *Injector) PreMutate(ctx context.Context, pod *corev1.Pod, parameters *processors.MutatorParameters) bool {
	logging.GetLogger().Info().Msgf("checking if need to inject sidecar")

	annotations := pod.ObjectMeta.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	status := annotations[SidecarAnnotationStatusKey]
	if strings.ToLower(status) == "injected" {
		logging.GetLogger().Info().Msg("pod has been injected")
		return false
	}

	labels := pod.ObjectMeta.Labels
	if in.isLabeled(labels, parameters.ClusterKey, parameters.Namespace) {
		if hasContainerPort(pod.Spec.Containers) && isReplicaSetOwned(pod.ObjectMeta.OwnerReferences) {
			logging.GetLogger().Info().Msg("pod will be injected")
			return true
		}
	}

	return false
}

func NewInjector(parameters *InjectionParameters) (*Injector, error) {
	injector := &Injector{params: parameters}
	return injector, nil
}

func createPatch(pod *corev1.Pod, original []byte) ([]jsonpatch.Operation, error) {
	reinjected, err := json.Marshal(pod)
	if err != nil {
		return nil, err
	}
	return jsonpatch.CreatePatch(original, reinjected)
}

func getAnnotation(meta metav1.ObjectMeta, name string, defaultValue interface{}) string {
	value, ok := meta.Annotations[name]
	if !ok {
		value = fmt.Sprint(defaultValue)
	}
	return value
}

func structToJSON(v interface{}) string {
	if v == nil {
		return "{}"
	}

	ba, err := json.Marshal(v)
	if err != nil {
		logging.GetLogger().Warn().Msgf("Unable to marshal %v", v)
		return "{}"
	}

	return string(ba)
}

func CreateInjectionFuncmap() template.FuncMap {
	return template.FuncMap{
		"annotation":   getAnnotation,
		"structToJSON": structToJSON,
	}
}

func applyOverlay(target *corev1.Pod, overlayJSON []byte) (*corev1.Pod, error) {
	currentJSON, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}

	pod := corev1.Pod{}
	// Overlay the injected template onto the original podSpec
	patched, err := strategicpatch.StrategicMergePatch(currentJSON, overlayJSON, pod)
	//fmt.Printf("after patch:\n%s\n", string(patched))
	if err != nil {
		return nil, fmt.Errorf("strategic merge: %v", err)
	}

	if err := json.Unmarshal(patched, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal patched pod: %v", err)
	}
	return &pod, nil
}

func parseTemplate(tmplStr string, data SidecarTemplateData) (bytes.Buffer, error) {
	var tmpl bytes.Buffer
	funcMap := CreateInjectionFuncmap()
	t, err := template.New("inject").Funcs(sprig.TxtFuncMap()).Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		logging.GetLogger().Warn().Msgf("Failed to parse template: %v %v\n", err, tmplStr)
		return bytes.Buffer{}, err
	}

	if err = t.Execute(&tmpl, &data); err != nil {
		logging.GetLogger().Warn().Msgf("Invalid template: %v %v\n", err, tmplStr)
		return bytes.Buffer{}, err
	}
	return tmpl, nil
}

func logPatches(patches []*processors.Patch) {
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to marshal patches")
		return
	}
	logging.GetLogger().Info().Msg(string(patchData))
}

func hasContainerPort(containers []corev1.Container) bool {
	for _, c := range containers {
		if c.Ports != nil || len(c.Ports) > 0 {
			return true
		}
	}
	return false
}

func isReplicaSetOwned(references []metav1.OwnerReference) bool {
	for _, or := range references {
		if or.Kind == "ReplicaSet" {
			return true
		}
	}
	return false
}

func (in *Injector) isLabeled(podLabels map[string]string, clusterKey, namespace string) bool {
	logging.GetLogger().Info().Msgf("pod labels: %+v", podLabels)
	if v, ok := podLabels["security-sidecar-inject"]; ok {
		if strings.ToLower(v) == "enabled" {
			return true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	ns, err := dal.GetNamespace(ctx, in.rdb, clusterKey, namespace)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("not found namespace %s", namespace)
		return false
	}
	if v, ok := ns.Labels["security-sidecar-inject"]; ok {
		if strings.ToLower(v) == "enabled" {
			return true
		}
	}
	return false
}

func (in *Injector) getPodOwner(ctx context.Context, pod *corev1.Pod, parameters *processors.MutatorParameters) (string, string) {
	for i := range pod.OwnerReferences {
		k := pod.OwnerReferences[i].Kind
		if k == "ReplicaSet" {
			query := dal.ResourcesQuery()
			query.WithCluster(parameters.ClusterKey)
			query.WithNamespace(parameters.Namespace)

			name := pod.OwnerReferences[i].Name
			n := strings.LastIndex(name, "-")
			deploymentName := ""
			if n > 0 {
				deploymentName = name[:n]
			}
			query.WithResourceName(deploymentName)
			var resources []*model.TensorResource
			var err error
			resources, err = dal.GetResources(ctx, in.rdb, query, 0, 1)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("get resource %s", deploymentName)
				query.WithResourceName(name)
				resources, err = dal.GetResources(ctx, in.rdb, query, 0, 1)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("get resource %s", name)
					continue
				}

				continue
			}
			if len(resources) > 0 {
				return resources[0].Name, resources[0].Kind
			}
			return "", ""
		}
	}
	return "", ""
}

func Register() {
	injector := Injector{}
	processors.Registry(injector.Name(), injector)
}

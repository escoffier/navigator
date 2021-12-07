package processors

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	app "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

//var ProcessorRegistry = make(map[string]reflect.Type)

type PodValidator interface {
	Validate(ctx context.Context, pod *core.Pod, parameters *ValidatingParameters) error
	PreValidate(ctx context.Context, pod *core.Pod, parameters *ValidatingParameters) bool
	Name() string
	Init(webHookConfig *WebHookConfig) error
}

type DeploymentValidator interface {
	Process(deployment app.Deployment)
}

type validatingChain struct {
	PodValidators        []PodValidator
	DeploymentValidators []DeploymentValidator
	validatingConfig     *ValidatingConfig
}

type ValidatingParameters struct {
	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	ClusterKey   string
	Namespace    string
	ResourceKind string
	ResourceName string
	Kind         string
}

type ValidatingConfig struct {
	IgnoredNameSpaces []string
	//RDB *rdbtools.GormWrapper
}

var ValidationFilterChain *validatingChain

func NewValidatorChain(config *ValidatingConfig) *validatingChain {
	return &validatingChain{validatingConfig: config}
}

func (c *validatingChain) validatePod(ctx context.Context, pod *core.Pod, parameters *ValidatingParameters) error {
	c.getPodOwner(pod, parameters)
	logging.GetLogger().Info().Msgf("parameters: %+v", *parameters)
	for _, v := range c.PodValidators {
		if v.PreValidate(ctx, pod, parameters) {
			err := v.Validate(ctx, pod, parameters)
			if err != nil {
				return err
			}
		} else {
			logging.GetLogger().Info().Msgf("skip validation for pods: %s", pod.Name)
		}
	}
	return nil
}

func (c *validatingChain) Validate(parameters ValidatingParameters, rawObj []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c.needValidating(parameters) {
		return nil
	}

	switch parameters.Kind {
	case "Pod":
		pod := &core.Pod{}
		if err := json.Unmarshal(rawObj, pod); err != nil {
			logging.GetLogger().Err(err).Msgf("Unmarshal raw object err")
			return err
		}
		err := c.validatePod(ctx, pod, &parameters)
		if err != nil {
			return err
		}
	default:
		logging.GetLogger().Error().Msgf("unsupported resource: %v", parameters.Kind)
	}
	return nil
}

func (c *validatingChain) AddValidator(validator interface{}) {
	vp, isPod := validator.(PodValidator)
	vd, isDeploy := validator.(DeploymentValidator)
	if isPod {
		logging.GetLogger().Info().Msgf("add pod validator: %s", vp.Name())
		c.PodValidators = append(c.PodValidators, vp)
	} else if isDeploy {
		logging.GetLogger().Info().Msgf("add deployment validator: %s", vp.Name())
		c.DeploymentValidators = append(c.DeploymentValidators, vd)
	} else {
		logging.GetLogger().Warn().Msgf("unknown validator: %v", validator)
	}
}

func (c *validatingChain) needValidating(resource ValidatingParameters) bool {
	for _, ns := range c.validatingConfig.IgnoredNameSpaces {
		if resource.Namespace == ns {
			logging.GetLogger().Debug().Msgf("ingored validating for resource %s in namespace %s", resource.Kind, ns)
			return true
		}
	}
	return false
}

func isDeploymentOwned(pod *core.Pod) bool {
	podLabels := pod.Labels
	if _, ok := podLabels["pod-template-hash"]; ok {
		return true
	}
	return false
}

func (c validatingChain) getPodOwner(pod *core.Pod, parameters *ValidatingParameters) {
	if pod.OwnerReferences == nil || len(pod.OwnerReferences) == 0 {
		parameters.ResourceKind = "Pod"
		parameters.ResourceName = pod.Name
		return
	}
	for i := range pod.OwnerReferences {
		k := pod.OwnerReferences[i].Kind
		name := pod.OwnerReferences[i].Name
		if k == "ReplicaSet" && isDeploymentOwned(pod) {
			n := strings.LastIndex(name, "-")
			deploymentName := ""
			if n > 0 {
				deploymentName = name[:n]
				parameters.ResourceKind = "Deployment"
				parameters.ResourceName = deploymentName
			}
		} else {
			parameters.ResourceKind = k
			parameters.ResourceName = name
		}
	}
}

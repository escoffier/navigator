package processors

import (
	"context"
	"encoding/json"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	app "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"time"
)

//var ProcessorRegistry = make(map[string]reflect.Type)

type PodValidator interface {
	Validate(ctx context.Context, pod *core.Pod, parameters *ValidatingParameters) error
	PreValidate(ctx context.Context, pod *core.Pod, parameters *ValidatingParameters) bool
	Name() string
	Init() error
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
	Namespace string
	Kind      string
}

type ValidatingConfig struct {
	IgnoredNameSpaces []string
}

var ValidationFilterChain *validatingChain

func NewValidatorChain(config *ValidatingConfig) *validatingChain {
	cf := &ValidatingConfig{
		IgnoredNameSpaces: config.IgnoredNameSpaces,
	}

	cf.IgnoredNameSpaces = append(cf.IgnoredNameSpaces, "kube-system", "tensorsec")
	return &validatingChain{validatingConfig: cf}
}

func (c *validatingChain) validatePod(ctx context.Context, pod *core.Pod, parameters *ValidatingParameters) error {
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
			return false
		}
	}
	return true
}

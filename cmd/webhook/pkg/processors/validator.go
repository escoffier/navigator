package processors

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	app "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

//var ProcessorRegistry = make(map[string]reflect.Type)

type PodValidator interface {
	Validate(pod *core.Pod, parameters *ValidatingParameters) error
	PreValidate(pod *core.Pod, parameters *ValidatingParameters) bool
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

func (c *validatingChain) validatePod(pod *core.Pod, parameters *ValidatingParameters) error {
	for _, v := range c.PodValidators {
		if v.PreValidate(pod, parameters) {
			err := v.Validate(pod, parameters)
			if err != nil {
				return err
			}
		} else {
			log.Infof("skip validation for pods: %s", pod.Name)
		}
	}
	return nil
}

func (c *validatingChain) Validate(parameters ValidatingParameters, rawObj []byte) error {
	//if !c.needValidating(parameters) {
	//	return nil
	//}
	switch parameters.Kind {
	case "Pod":
		pod := &core.Pod{}
		if err := json.Unmarshal(rawObj, pod); err != nil {
			return err
		}
		err := c.validatePod(pod, &parameters)
		if err != nil {
			return err
		}
	default:
		log.Errorf("unsupported resource: %v", parameters.Kind)
		//return fmt.Errorf()
	}
	return nil
}

func (c *validatingChain) AddValidator(validator interface{}) {
	log.Infof("add validator: %v", validator)
	vp, isPod := validator.(PodValidator)
	vd, isDeploy := validator.(DeploymentValidator)
	if isPod {
		c.PodValidators = append(c.PodValidators, vp)
	} else if isDeploy {
		c.DeploymentValidators = append(c.DeploymentValidators, vd)
	} else {
		log.Warnf("unkonown validator: %v", validator)
	}
}

func (c *validatingChain) needValidating(resource ValidatingParameters) bool {
	for _, ns := range c.validatingConfig.IgnoredNameSpaces {
		if resource.Namespace == ns {
			log.Debugf("ingored validating for resource %s in namespace %s", resource.Kind, ns)
			return false
		}
	}
	return true
}

package fileters

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	app "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

type PodValidator interface {
	Validate(pod *core.Pod) error
}

type DeploymentFilter interface {
	Process(deployment app.Deployment)
}

type filterChain struct {
	PodValidators     []PodValidator
	DeploymentFilters []DeploymentFilter
	validatingConfig  *ValidatingConfig
}

type ValidatingParameters struct {
	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	Namespace string
	Kind      string
}

type ValidatingConfig struct {
	IgnoredNameSpaces []string
}

var ValidationFilterChain *filterChain

func NewFilterChain(config *ValidatingConfig) *filterChain {
	cf := &ValidatingConfig{
		IgnoredNameSpaces: config.IgnoredNameSpaces,
	}

	cf.IgnoredNameSpaces = append(cf.IgnoredNameSpaces, "kube-system", "tensorsec")
	return &filterChain{validatingConfig: cf}
}

func (c *filterChain) processPod(pod *core.Pod) error {
	for _, f := range c.PodValidators {
		err := f.Validate(pod)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *filterChain) Validate(request ValidatingParameters, rawObj []byte) error {
	if !c.needValidating(request) {
		return nil
	}
	switch request.Kind {
	case "Pod":
		pod := &core.Pod{}
		if err := json.Unmarshal(rawObj, pod); err != nil {
			return err
		}
		err := c.processPod(pod)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *filterChain) AddPodFilter(filter PodValidator) {
	log.Infof("add filter: %v", filter)
	c.PodValidators = append(c.PodValidators, filter)
}

func (c *filterChain) needValidating(resource ValidatingParameters) bool {
	for _, ns := range c.validatingConfig.IgnoredNameSpaces {
		if resource.Namespace == ns {
			log.Debugf("ingored validating for resource %s in namespace %s", resource.Kind, ns)
			return false
		}
	}
	return true
}

func init() {
	//ValidationFilterChain = NewFilterChain()
}

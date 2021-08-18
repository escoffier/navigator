package processors

import (
	"context"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	core "k8s.io/api/core/v1"
	"time"
)

var MutatorChain *mutatorChain

type PodMutator interface {
	Name() string
	Init() error
	Mutate(ctx context.Context, parameters *MutatorParameters, pod *core.Pod) []*Patch
	PreMutate(ctx context.Context, pod *core.Pod, parameters *MutatorParameters) bool
}

type ConfigMapMutator interface {
	Name() string
	Init() error
	Mutate(ctx context.Context, parameters *MutatorParameters, cm *core.ConfigMap) []*Patch
	PreMutate(ctx context.Context, cm *core.ConfigMap, parameters *MutatorParameters) bool
}

type mutatorChain struct {
	podMutators []PodMutator
	cmMutators  []ConfigMapMutator
}

type MutatorParameters struct {
	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	Namespace string
	Kind      string
	Cluster   string
}

func (m *mutatorChain) AddMutator(mutator interface{}) {
	vp, isPod := mutator.(PodMutator)
	if isPod {
		log.Infof("add pod mutator: %s", vp.Name())
		m.podMutators = append(m.podMutators, vp)
	}
}

func (m *mutatorChain) Mutate(parameters *MutatorParameters, rawObj []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var patch []byte
	switch parameters.Kind {
	case "Pod":
		pod := &core.Pod{}
		if err := json.Unmarshal(rawObj, pod); err != nil {
			log.Errorf("failed to Unmarshal pod: %v", err)
			return nil
		}
		patch = m.mutatePod(ctx, parameters, pod)
	case "ConfigMap":
		cm := &core.ConfigMap{}
		if err := json.Unmarshal(rawObj, cm); err != nil {
			log.Errorf("failed to Unmarshal configmap: %v", err)
			return nil
		}
		patch = m.mutateConfigMap(ctx, parameters, cm)
	default:
		log.Errorf("unsupported resource: %v", parameters.Kind)
	}
	return patch
}

func (m *mutatorChain) mutatePod(ctx context.Context, parameters *MutatorParameters, pod *core.Pod) []byte {
	var patches []*Patch
	for _, m := range m.podMutators {
		log.Debugf("mutatePod by %s", m.Name())
		p := m.Mutate(ctx, parameters, pod)
		patches = append(patches, p...)
	}
	log.Debugf("pod patches: %v", patches)
	patchData, err := json.Marshal(patches)
	if err != nil {
		log.Errorf("failed to marshal patches")
		return nil
	}
	return patchData
}

func (m *mutatorChain) mutateConfigMap(ctx context.Context, parameters *MutatorParameters, cm *core.ConfigMap) []byte {
	var patches []*Patch
	for _, m := range m.cmMutators {
		p := m.Mutate(ctx, parameters, cm)
		patches = append(patches, p...)
	}
	log.Debugf("patches: %v", patches)
	patchData, err := json.Marshal(patches)
	if err != nil {
		log.Errorf("failed to marshal patches")
		return nil
	}
	return patchData
	//return patches
}

func NewMutatorChain() *mutatorChain {
	return &mutatorChain{}
}

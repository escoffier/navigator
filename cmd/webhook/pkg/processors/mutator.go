package processors

import (
	"context"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"time"
)

var MutatorChain *mutatorChain

type PodMutator interface {
	Name() string
	Init() error
	Mutate(ctx context.Context, parameters *MutatorParameters, pod *corev1.Pod) []*Patch
	PreMutate(ctx context.Context, pod *corev1.Pod, parameters *MutatorParameters) bool
}

type ConfigMapMutator interface {
	Name() string
	Init() error
	Mutate(ctx context.Context, parameters *MutatorParameters, cm *corev1.ConfigMap) []*Patch
	PreMutate(ctx context.Context, cm *corev1.ConfigMap, parameters *MutatorParameters) bool
}

type NamespaceMutator interface {
	Name() string
	Init() error
	NamespaceMutate(ctx context.Context, parameters *MutatorParameters, ns *corev1.Namespace) []*Patch
	PreNamespaceMutate(ctx context.Context, ns *corev1.Namespace, parameters *MutatorParameters) bool
}

type mutatorChain struct {
	podMutators []PodMutator
	cmMutators  []ConfigMapMutator
	nsMutators  []NamespaceMutator
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
	nsMu, isNs := mutator.(NamespaceMutator)
	if isNs {
		log.Infof("add namespace mutator: %s", nsMu.Name())
		m.nsMutators = append(m.nsMutators, nsMu)
	}
}

func (m *mutatorChain) Mutate(parameters *MutatorParameters, rawObj []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var patch []byte
	switch parameters.Kind {
	case "Pod":
		pod := &corev1.Pod{}
		if err := json.Unmarshal(rawObj, pod); err != nil {
			log.Errorf("failed to Unmarshal pod: %v", err)
			return nil
		}
		patch = m.mutatePod(ctx, parameters, pod)
	case "ConfigMap":
		cm := &corev1.ConfigMap{}
		if err := json.Unmarshal(rawObj, cm); err != nil {
			log.Errorf("failed to Unmarshal configmap: %v", err)
			return nil
		}
		patch = m.mutateConfigMap(ctx, parameters, cm)
	case "Namespace":
		ns := &corev1.Namespace{}
		if err := json.Unmarshal(rawObj, ns); err != nil {
			log.Errorf("failed to Unmarshal configmap: %v", err)
			return nil
		}
		patch = m.mutateNamespace(ctx, parameters, ns)
	default:
		log.Errorf("unsupported resource: %v", parameters.Kind)
	}
	return patch
}

func (m *mutatorChain) mutatePod(ctx context.Context, parameters *MutatorParameters, pod *corev1.Pod) []byte {
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

func (m *mutatorChain) mutateConfigMap(ctx context.Context, parameters *MutatorParameters, cm *corev1.ConfigMap) []byte {
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

func (m *mutatorChain) mutateNamespace(ctx context.Context, parameters *MutatorParameters, ns *corev1.Namespace) []byte {
	var patches []*Patch
	for _, m := range m.nsMutators {
		p := m.NamespaceMutate(ctx, parameters, ns)
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

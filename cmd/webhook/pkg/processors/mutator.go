package processors

import (
	"context"
	"encoding/json"
	"errors"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
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
	config      *MutatingConfig
}

type MutatorParameters struct {
	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	Namespace  string
	Kind       string
	ClusterKey string
	rdb        *rdbtools.GormWrapper
}

type MutatingConfig struct {
	IgnoredNameSpaces []string
}

func (m *mutatorChain) AddMutator(mutator interface{}) {
	vp, isPod := mutator.(PodMutator)
	if isPod {
		logging.GetLogger().Info().Msgf("add pod mutator: %s", vp.Name())
		m.podMutators = append(m.podMutators, vp)
	}
	nsMu, isNs := mutator.(NamespaceMutator)
	if isNs {
		logging.GetLogger().Info().Msgf("add namespace mutator: %s", nsMu.Name())
		m.nsMutators = append(m.nsMutators, nsMu)
	}
}

func (m *mutatorChain) Mutate(parameters *MutatorParameters, rawObj []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if m.needMutating(parameters) {
		return nil
	}
	var patch []byte
	switch parameters.Kind {
	case "Pod":
		pod := &corev1.Pod{}
		if err := json.Unmarshal(rawObj, pod); err != nil {
			logging.GetLogger().Err(err).Msg("failed to Unmarshal pod")
			return nil
		}
		patch = m.mutatePod(ctx, parameters, pod)
	case "ConfigMap":
		cm := &corev1.ConfigMap{}
		if err := json.Unmarshal(rawObj, cm); err != nil {
			logging.GetLogger().Err(err).Msg("failed to Unmarshal configmap")
			return nil
		}
		patch = m.mutateConfigMap(ctx, parameters, cm)
	//case "Namespace":
	//	ns := &corev1.Namespace{}
	//	if err := json.Unmarshal(rawObj, ns); err != nil {
	//		logging.GetLogger().Err(err).Msg("failed to Unmarshal namespace")
	//		return nil
	//	}
	//	patch = m.mutateNamespace(ctx, parameters, ns)
	default:
		logging.GetLogger().Err(errors.New("unsupported resource kind")).Msg(parameters.Kind)
	}
	return patch
}

func (m *mutatorChain) mutatePod(ctx context.Context, parameters *MutatorParameters, pod *corev1.Pod) []byte {
	var patches []*Patch
	for _, m := range m.podMutators {
		if m.PreMutate(ctx, pod, parameters) {
			logging.GetLogger().Debug().Msgf("mutatePod by %s", m.Name())
			p := m.Mutate(ctx, parameters, pod)
			patches = append(patches, p...)
		}
	}
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to marshal patches")
		return nil
	}
	logging.GetLogger().Info().Msg(string(patchData))
	return patchData
}

func (m *mutatorChain) mutateConfigMap(ctx context.Context, parameters *MutatorParameters, cm *corev1.ConfigMap) []byte {
	var patches []*Patch
	for _, m := range m.cmMutators {
		p := m.Mutate(ctx, parameters, cm)
		patches = append(patches, p...)
	}
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to marshal patches")
		return nil
	}
	logging.GetLogger().Info().Msg(string(patchData))
	return patchData
}

func (m *mutatorChain) mutateNamespace(ctx context.Context, parameters *MutatorParameters, ns *corev1.Namespace) []byte {
	var patches []*Patch
	for _, m := range m.nsMutators {
		p := m.NamespaceMutate(ctx, parameters, ns)
		patches = append(patches, p...)
	}
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to marshal patches")
		return nil
	}
	logging.GetLogger().Info().Msg(string(patchData))
	return patchData
}

func (m *mutatorChain) needMutating(resource *MutatorParameters) bool {
	for _, ns := range m.config.IgnoredNameSpaces {
		if resource.Namespace == ns {
			logging.GetLogger().Debug().Msgf("ignored mutating for resource %s in namespace %s", resource.Kind, ns)
			return true
		}
	}
	return false
}

func NewMutatorChain(config *MutatingConfig) *mutatorChain {
	return &mutatorChain{config: config}
}

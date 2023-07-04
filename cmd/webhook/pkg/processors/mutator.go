package processors

import (
	"context"
	"encoding/json"
	"errors"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
)

var MutatorChain *mutatorChain

type PodMutator interface {
	Name() string
	Init(webHookConfig *WebHookConfig) error
	Mutate(ctx context.Context, parameters *MutatorParameters, pod *corev1.Pod) ([]*Patch, error)
	PreMutate(ctx context.Context, pod *corev1.Pod, parameters *MutatorParameters) bool
}

type ConfigMapMutator interface {
	Name() string
	Init(webHookConfig *WebHookConfig) error
	Mutate(ctx context.Context, parameters *MutatorParameters, cm *corev1.ConfigMap) []*Patch
	PreMutate(ctx context.Context, cm *corev1.ConfigMap, parameters *MutatorParameters) bool
}

type NamespaceMutator interface {
	Name() string
	Init(webHookConfig *WebHookConfig) error
	NamespaceMutate(ctx context.Context, parameters *MutatorParameters, ns *corev1.Namespace) ([]*Patch, error)
	PreNamespaceMutate(ctx context.Context, ns *corev1.Namespace, parameters *MutatorParameters) bool
}

type mutatorChain struct {
	podMutators []PodMutator
	cmMutators  []ConfigMapMutator
	nsMutators  []NamespaceMutator
	config      *MutatingConfig
}

type MutatorParameters struct {
	Kind         string
	Namespace    string
	ResourceKind string
	ResourceName string
	ClusterKey   string
	rdb          *databases.RDBInstance
}

type MutatingConfig struct {
	IgnoredNameSpaces []string
}

func (m *mutatorChain) AddMutator(mutator interface{}) {
	vp, isPod := mutator.(PodMutator)
	if isPod {
		logging.Get().Info().Msgf("add pod mutator: %s", vp.Name())
		m.podMutators = append(m.podMutators, vp)
	}
	nsMu, isNs := mutator.(NamespaceMutator)
	if isNs {
		logging.Get().Info().Msgf("add namespace mutator: %s", nsMu.Name())
		m.nsMutators = append(m.nsMutators, nsMu)
	}
}

func (m *mutatorChain) Mutate(ctx context.Context, parameters *MutatorParameters, rawObj []byte) ([]byte, error) {
	if m.needMutating(parameters) {
		return nil, nil
	}
	var patch []byte
	var err error
	switch parameters.Kind {
	case "Pod":
		pod := &corev1.Pod{}
		if err := json.Unmarshal(rawObj, pod); err != nil {
			logging.Get().Err(err).Msg("failed to Unmarshal pod")
			return nil, nil
		}
		patch, err = m.mutatePod(ctx, parameters, pod)
	case "ConfigMap":
		cm := &corev1.ConfigMap{}
		if err := json.Unmarshal(rawObj, cm); err != nil {
			logging.Get().Err(err).Msg("failed to Unmarshal configmap")
			return nil, nil
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
		logging.Get().Err(errors.New("unsupported resource kind")).Msg(parameters.Kind)
	}
	return patch, err
}

func (m *mutatorChain) mutatePod(ctx context.Context, parameters *MutatorParameters, pod *corev1.Pod) ([]byte, error) {
	var patches []*Patch
	var err error
	for _, m := range m.podMutators {
		if m.PreMutate(ctx, pod, parameters) {
			logging.Get().Debug().Msgf("mutate Pod by %s", m.Name())
			p, err := m.Mutate(ctx, parameters, pod)
			if err != nil {
				logging.Get().Warn().Msgf("mutate err: %v", err)
				return nil, err
			}
			patches = append(patches, p...)
		}
	}
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.Get().Err(err).Msg("failed to marshal patches")
		return nil, nil
	}
	logging.Get().Info().Msg(string(patchData))
	return patchData, nil
}

func (m *mutatorChain) mutateConfigMap(ctx context.Context, parameters *MutatorParameters, cm *corev1.ConfigMap) []byte {
	var patches []*Patch
	for _, m := range m.cmMutators {
		p := m.Mutate(ctx, parameters, cm)
		patches = append(patches, p...)
	}
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.Get().Err(err).Msg("failed to marshal patches")
		return nil
	}
	logging.Get().Info().Msg(string(patchData))
	return patchData
}

func (m *mutatorChain) mutateNamespace(ctx context.Context, parameters *MutatorParameters, ns *corev1.Namespace) ([]byte, error) {
	var patches []*Patch
	for _, m := range m.nsMutators {
		p, err := m.NamespaceMutate(ctx, parameters, ns)
		if err != nil {
			return nil, err
		}
		patches = append(patches, p...)
	}
	patchData, err := json.Marshal(patches)
	if err != nil {
		logging.Get().Err(err).Msg("failed to marshal patches")
		return nil, nil
	}
	logging.Get().Info().Msg(string(patchData))
	return patchData, nil
}

func (m *mutatorChain) needMutating(resource *MutatorParameters) bool {
	for _, ns := range m.config.IgnoredNameSpaces {
		if resource.Namespace == ns {
			logging.Get().Debug().Msgf("ignored mutating for resource %s in namespace %s", resource.Kind, ns)
			return true
		}
	}
	return false
}

func NewMutatorChain(config *MutatingConfig) *mutatorChain {
	return &mutatorChain{config: config}
}

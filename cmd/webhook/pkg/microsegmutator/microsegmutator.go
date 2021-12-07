package microsegmutator

import (
	"context"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/config"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/service"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	v1 "k8s.io/api/core/v1"
)

type MicroSegMutator struct {
	svc service.Service
}

var _ processors.NamespaceMutator = (*MicroSegMutator)(nil)
var _ processors.PodMutator = (*MicroSegMutator)(nil)

func (m *MicroSegMutator) Mutate(ctx context.Context, parameters *processors.MutatorParameters, pod *v1.Pod) []*processors.Patch {
	log.Info("MicroSegMutator for Pod processing")
	return m.svc.MutateLabels(ctx, parameters, pod)
}

func (m *MicroSegMutator) NamespaceMutate(ctx context.Context, parameters *processors.MutatorParameters, ns *v1.Namespace) []*processors.Patch {
	log.Info("MicroSegMutator for Namespace processing")
	return m.svc.MutateNamespaceLabels(ctx, parameters, ns)
}

func (m *MicroSegMutator) PreMutate(_ context.Context, _ *v1.Pod, _ *processors.MutatorParameters) bool {
	return true
}

func (m *MicroSegMutator) PreNamespaceMutate(_ context.Context, _ *v1.Namespace, _ *processors.MutatorParameters) bool {
	return true
}

func (m *MicroSegMutator) Name() string {
	return "MicroSegMutator"
}

func (m *MicroSegMutator) Init(webHookConfig *processors.WebHookConfig) error {
	log.Info("init MicroSegMutator")
	err := config.InitMutationConfig()
	if err != nil {
		log.Errorf("load config failed: %v", err)
		return err
	}
	m.svc = service.NewMutationService(webHookConfig.RDB, config.MutationK8sCli)
	return nil
}

func Register() {
	var m = MicroSegMutator{}
	processors.Registry(m.Name(), m)
}

package immune

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/immune/config"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/immune/mutation"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	failureRetryInterval = time.Second * 30
	reloadInterval       = time.Minute
	preset               = "presets.yaml"
)

type immuneMutator struct {
	holder *config.Holder
}

func (i immuneMutator) Name() string {
	return "ImmuneMutator"
}

func Register() {
	m := immuneMutator{}
	processors.Registry(m.Name(), m)
	logging.GetLogger().Info().Msg("Registering immune mutator")
}

func (i *immuneMutator) Init(webHookConfig *processors.WebHookConfig) error {
	var c *rest.Config
	c, err := rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
		return err
	}
	clientset, err := kubernetes.NewForConfig(c)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to create k8s client")
		return err
	}

	holder, err := config.NewReloadingConfig(processors.GetConfigFullPath(preset), webHookConfig.RDB, clientset, &config.ReloadConfig{
		FailureRetryInterval: failureRetryInterval,
		ReloadInterval:       reloadInterval,
	})
	if err != nil {
		logging.GetLogger().Error().Msgf("Failed to load config: %v", err)
		return err
	}
	i.holder = holder
	logging.GetLogger().Info().Msg("Immune mutator initialized")
	return nil
}

func (i immuneMutator) PreMutate(ctx context.Context, pod *v1.Pod, parameters *processors.MutatorParameters) bool {
	return true
}

func (i immuneMutator) Mutate(ctx context.Context, pod *v1.Pod, parameters *processors.MutatorParameters) []*processors.Patch {
	logging.GetLogger().Debug().Msg("Immune mutator mutate")
	patches := mutation.MakePatches(ctx, i.holder.Get(), i.holder.K8sCli, i.holder.DB, pod, parameters)
	return patches
}

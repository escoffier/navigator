package driftprevention

import (
	"context"
	flag "github.com/spf13/pflag"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/driftprevention/config"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/driftprevention/mutation"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	v1 "k8s.io/api/core/v1"
	"time"
)

var (
	failureRetryInterval = time.Second * 30
	reloadInterval       = time.Minute
	preset               = "presets.yaml"
)

//const preset = "config/presets.yaml"

type driftPreventionMutator struct {
	holder *config.Holder
}

func (d driftPreventionMutator) Name() string {
	return "DriftPreventionMutator"
}

func (d *driftPreventionMutator) Init() error {
	holder, err := config.NewReloadingConfig(processors.GetConfigFullPath(preset), &config.ReloadConfig{
		FailureRetryInterval: failureRetryInterval,
		ReloadInterval:       reloadInterval,
	})

	if err != nil {
		return err
	}
	d.holder = holder
	return nil
}

func (d *driftPreventionMutator) Mutate(ctx context.Context, parameters *processors.MutatorParameters, pod *v1.Pod) []*processors.Patch {
	patches := mutation.PatchPod(d.holder.Get(), pod)
	return patches
	//patchData, err := json.Marshal(patches)
	//if err != nil {
	//	logrus.Errorf("mash patch failed")
	//	return nil
	//}
	//return patchData
}

func (d driftPreventionMutator) PreMutate(ctx context.Context, pod *v1.Pod, parameters *processors.MutatorParameters) bool {
	return true
}

func Register() {
	m := driftPreventionMutator{}
	processors.Registry(m.Name(), m)
}

func init() {
	flag.DurationVar(&failureRetryInterval, "retry-interval", failureRetryInterval, "(optional) specify the duration between reloads on failure")
	flag.DurationVar(&reloadInterval, "reload-interval", reloadInterval, "(optional) specify the duration between reloads on success")
	flag.StringVar(&preset, "preset", preset, "(optional)  file name container cluster presets")
}

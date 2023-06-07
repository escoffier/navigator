package registry

import (
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/dispatcher/dequeuers"
	imageModel "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type DequeueRegistryImageTask struct {
}

func (d *DequeueRegistryImageTask) Type() dequeuers.DequeueType {
	return dequeuers.TypeRegistryImageTask
}

func (d *DequeueRegistryImageTask) Pop() ([]imageModel.ScanSubTask, error) {
	// todo: select tasks from db
	return nil, nil
}

func init() {
	dequeuers.RegisterDequeuer(&DequeueRegistryImageTask{})
}

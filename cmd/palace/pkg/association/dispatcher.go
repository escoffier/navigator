package association

import (
	"context"
	"hash/fnv"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

type DispatchConfig struct {
	ParallelNum uint32
}
type EventDispatcher struct {
	config            DispatchConfig
	associationConfig AssociationConfiguration
	rdb               *rdbtools.GormWrapper

	processors []*AssociationProcessor
}

func NewEventDispatcher(config DispatchConfig, associationConfig AssociationConfiguration, rdb *rdbtools.GormWrapper) (*EventDispatcher, error) {
	disp := new(EventDispatcher)
	disp.config = config
	disp.associationConfig = associationConfig
	disp.rdb = rdb
	disp.initProcessors()

	return disp, nil
}

func (d *EventDispatcher) initProcessors() {
	d.processors = make([]*AssociationProcessor, d.config.ParallelNum)
	for i := 0; uint32(i) < d.config.ParallelNum; i++ {
		d.processors[i] = NewAssociationProcessor(d.associationConfig, d.rdb)
	}
}

func uuid(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
func (d *EventDispatcher) getProcessor(groupbyKey string) *AssociationProcessor {
	return d.processors[uuid(groupbyKey)%d.config.ParallelNum]
}
func (d *EventDispatcher) ProcessEvent(ctx context.Context, event PodContainerEvent) error {
	loc, ok := event.Location()
	if !ok {
		return nil
	}

	proc := d.getProcessor(loc.String())
	return proc.Send(ctx, event)
}

package association

import (
	"context"
	"hash/fnv"

	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

type DispatchConfig struct {
	ParallelNum uint32
}
type EventDispatcher struct {
	config            DispatchConfig
	associationConfig Configuration
	rdb               *rdbtools.GormWrapper
	rulesManager      *echelper.RulesManager

	processors []*Processor
}

func NewEventDispatcher(config DispatchConfig, associationConfig Configuration, rdb *rdbtools.GormWrapper, rulesManager *echelper.RulesManager) (*EventDispatcher, error) {
	disp := new(EventDispatcher)
	disp.config = config
	disp.associationConfig = associationConfig
	disp.rdb = rdb
	disp.rulesManager = rulesManager
	disp.initProcessors()

	return disp, nil
}

func (d *EventDispatcher) initProcessors() {
	d.processors = make([]*Processor, d.config.ParallelNum)
	for i := 0; uint32(i) < d.config.ParallelNum; i++ {
		d.processors[i] = NewAssociationProcessor(d.associationConfig, d.rdb, d.rulesManager)
	}
}

func uuid(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
func (d *EventDispatcher) getProcessor(groupbyKey string) *Processor {
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

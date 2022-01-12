package association

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// receives events by constant events from the same pods
type AssociationProcessor struct {
	aggregators map[string]*ProcessTreeAggregator // key: targetLocation

	inputsChan chan PodContainerEvent
	eventsChan chan AssociationEvent

	config       AssociationConfiguration
	rdb          *rdbtools.GormWrapper
	rulesManager *echelper.RulesManager
}

func NewAssociationProcessor(config AssociationConfiguration, rdb *rdbtools.GormWrapper, rulesManager *echelper.RulesManager) *AssociationProcessor {
	proc := AssociationProcessor{
		aggregators:  make(map[string]*ProcessTreeAggregator, 10),
		inputsChan:   make(chan PodContainerEvent, 50),
		eventsChan:   make(chan AssociationEvent, 250),
		config:       config,
		rdb:          rdb,
		rulesManager: rulesManager,
	}

	proc.asyncLoop()

	return &proc
}

func (ap *AssociationProcessor) Send(ctx context.Context, e PodContainerEvent) error {
	_, ok := e.Location()
	if !ok {
		return nil
	}

	if _, setted := ctx.Deadline(); !setted {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
	}
	select {
	case ap.inputsChan <- e:
		return nil
	case <-ctx.Done():
		return ErrTimeout
	}
}

func (ap *AssociationProcessor) getOrCreateAggregator(location TargetLocation) *ProcessTreeAggregator {
	locationStr := location.String()
	aggr, exist := ap.aggregators[locationStr]
	if !exist {
		aggr = NewProcessTreeAggregator(ap.config, location, ap.eventsChan)
		ap.aggregators[locationStr] = aggr
	}

	return aggr
}
func (ap *AssociationProcessor) handleEvent(ctx context.Context, e PodContainerEvent) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when handle event %v. stack: %s", r, debug.Stack())
			err = ErrPanic
		}
	}()

	loc, ok := e.Location()
	if ok {
		aggr := ap.getOrCreateAggregator(loc)
		err := aggr.AddEvent(context.Background(), e)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("Error adding event %+v.", e)
			return err
		}
	}
	return nil
}

func (ap *AssociationProcessor) generateAGEvent(ctx context.Context, evt AssociationEvent, now time.Time) (*model.PalaceAssociatedGraphEvent, error) {
	e := new(model.PalaceAssociatedGraphEvent)
	e.ID = evt.GetID()
	locationsMap := make(map[string]model.Location, 2)
	maxSeverity := uint32(0)
	maxCnt := 0
	for _, evt := range evt.GetEvents() {
		loc, ok := evt.Location()
		if ok {
			if _, exist := locationsMap[loc.String()]; exist {
				continue
			}
			locElems := make([]string, 0, 3)

			for i := 0; ; i++ {
				item, ok := loc.GetLocationElem(i)
				if !ok {
					break
				}
				locElems = append(locElems, item)
			}
			locModel := model.Location{
				ClusterKey:    loc.ClusterKey(),
				Type:          string(loc.Type()),
				LocationElems: locElems,
				Expr:          loc.String(),
			}
			locationsMap[loc.String()] = locModel
		}

		rule, exist := ap.rulesManager.GetRule(evt.module, evt.category, evt.rule)
		if exist {
			if rule.Severity > maxSeverity {
				maxSeverity = rule.Severity
				maxCnt = 1
			} else if rule.Severity == maxSeverity {
				maxCnt++
			}
		}
	}
	e.Locations = make([]model.Location, 0, len(locationsMap))
	for _, l := range locationsMap {
		e.Locations = append(e.Locations, l)
	}
	e.NodesNum = evt.GetNodesNum()
	e.EventsNum = evt.GetEventsNum()
	e.AssociationKind = "process_tree"
	e.CreatedAt = now
	e.UpdatedAt = now
	if maxCnt > 2 {
		maxSeverity += 2
		if maxSeverity > 10 {
			maxSeverity = 10
		}
	}
	e.Severity = maxSeverity
	return e, nil
}
func (ap *AssociationProcessor) createAGEvent(ctx context.Context, evt AssociationEvent, now time.Time) (uint64, error) {
	evtModel, err := ap.generateAGEvent(ctx, evt, now)
	if err != nil {
		return 0, err
	}

	return dal.UpsertAssociatedGraphEvent(ctx, ap.rdb.Get(), evtModel)
}

// createSignalAssociations uses transaction to ensure the consistency.
func (ap *AssociationProcessor) createSignalAssociations(ctx context.Context, agEvtID uint64, evt AssociationEvent, now time.Time) error {
	for _, evt := range evt.GetEvents() {
		asso := new(model.PalaceEventSignalAssociation)
		asso.AggrEvtID = agEvtID
		l, ok := evt.Location()
		if ok {
			asso.AggrKey = fmt.Sprintf("%s/%s", l.String(), evt.AggregationKey())
		} else {
			asso.AggrKey = evt.AggregationKey()
		}
		asso.SignalID = evt.ID()
		asso.CreatedAt = now
		err := util.RetryWithBackoff(ctx, func() error {
			_, err := dal.CreateSignalAssociation(ctx, ap.rdb.Get(), asso)
			return err
		}, retry.Attempts(2))
		if err != nil {
			logging.GetLogger().Err(err).Msgf("create signal association error", err)
		}

	}
	return nil
}

func (ap *AssociationProcessor) createAssociationLinks(ctx context.Context, agEvtID uint64, evt AssociationEvent, now time.Time) error {
	for _, link := range evt.GetAssociatedLinks() {
		linkModel := new(model.PalaceAssociationLink)
		linkModel.AggrEvtID = agEvtID
		linkModel.CreatedAt = now
		linkModel.SrcClusterKey = link.SrcLoc.ClusterKey()
		linkModel.SrcLocType = string(link.SrcLoc.Type())
		sb := strings.Builder{}
		sb.WriteString(link.SrcLoc.String())
		sb.WriteRune('/')
		sb.WriteString(link.SrcAggrKey)
		linkModel.SrcLocExpr = sb.String()
		linkModel.DestClusterKey = link.DestLoc.ClusterKey()
		linkModel.DestLocType = string(link.DestLoc.Type())
		sb = strings.Builder{}
		sb.WriteString(link.DestLoc.String())
		sb.WriteRune('/')
		sb.WriteString(link.DestAggrKey)
		linkModel.DestLocExpr = sb.String()
		linkModel.CreatedAt = now

		err := util.RetryWithBackoff(ctx, func() error {
			_, err := dal.CreateAssociationLinks(ctx, ap.rdb.Get(), linkModel)
			return err
		}, retry.Attempts(2))
		if err != nil {
			logging.GetLogger().Err(err).Msgf("create association link error", err)
		}
	}
	return nil
}

func (ap *AssociationProcessor) upsertAssociationGraphEvent(ctx context.Context, evt AssociationEvent) (uint64, error) {
	now := time.Now()
	evtID, err := ap.createAGEvent(ctx, evt, now)
	if err != nil {
		return 0, err
	}
	evt.SetID(evtID)

	tctx, cancel := context.WithTimeout(ctx, 10000*time.Millisecond)
	defer cancel()

	err = ap.createSignalAssociations(tctx, evtID, evt, now)
	if err != nil {
		return 0, err
	}

	err = ap.createAssociationLinks(tctx, evtID, evt, now)
	return evtID, err
}

func (ap *AssociationProcessor) handleAssocatedEvent(ctx context.Context, evt AssociationEvent) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when handleAssocatedEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	tctx, cancel := context.WithTimeout(ctx, ap.config.BuildInterval*9/10)
	defer cancel()

	evtID, err := ap.upsertAssociationGraphEvent(tctx, evt)
	evt.PostActionSetting(evtID, err == nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("upsert agraph event err. evt: %+v", evt)
		return err
	}
	return nil
}

func (ap *AssociationProcessor) cleanUp(now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when cleanUp: %v. stack: %s", r, debug.Stack())
		}
	}()

	toClean := make(map[string]struct{}, 5)
	for key, aggr := range ap.aggregators {
		if now.Sub(aggr.updatedAt) >= ap.config.WindowDivisionLatency {
			aggr.RequireStop()
			toClean[key] = struct{}{}
		}
	}

	logging.GetLogger().Info().Msgf("to clean aggregators: %v", toClean)
	for key, _ := range toClean {
		delete(ap.aggregators, key)
	}
}
func (ap *AssociationProcessor) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic for AssociationProcessor: %v. Stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(ap.config.BuildInterval)
		defer ticker.Stop()

		for {
			select {
			case e := <-ap.inputsChan:
				err := ap.handleEvent(context.Background(), e)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("handle event error. event: %+v", e)
				}
			case aevt := <-ap.eventsChan:
				err := ap.handleAssocatedEvent(context.Background(), aevt)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("handle association event error. event: %+v", aevt)
				}
			case now := <-ticker.C:
				ap.cleanUp(now)
			}
		}
	}()
}

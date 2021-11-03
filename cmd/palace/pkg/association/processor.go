package association

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
)

// receives events by constant events from the same pods
type AssociationProcessor struct {
	aggregators map[string]*ProcessTreeAggregator // key: targetLocation

	inputsChan chan *PodContainerEvent
	eventsChan chan AssociationEvent

	config AssociationConfiguration
	rdb    *rdbtools.GormWrapper
}

func (ap *AssociationProcessor) Send(ctx context.Context, e *PodContainerEvent) error {
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

	return nil
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
func (ap *AssociationProcessor) handleEvent(ctx context.Context, e *PodContainerEvent) (err error) {
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
	eventsNum := int64(0)
	aggrKeysMap := make(map[string]struct{}, 10)
	for _, evt := range evt.GetEvents() {
		aggrKeysMap[evt.AggregationKey()] = struct{}{}
		eventsNum++
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
	}
	e.Locations = make([]model.Location, 0, len(locationsMap))
	for _, l := range locationsMap {
		e.Locations = append(e.Locations, l)
	}
	e.NodesNum = int64(len(aggrKeysMap))
	e.EventsNum = eventsNum
	e.AssociationKind = "process_tree"
	e.CreatedAt = now
	// TODO missing severity

	return e, nil
}
func (ap *AssociationProcessor) createAGEvent(ctx context.Context, evt AssociationEvent, now time.Time) (int64, error) {
	evtModel, err := ap.generateAGEvent(ctx, evt, now)
	if err != nil {
		return 0, err
	}

	return dal.UpsertAssociatedGraphEvent(ctx, ap.rdb.Get(), evtModel)
}

// createSignalAssociations uses transaction to ensure the consistency.
func (ap *AssociationProcessor) createSignalAssociations(ctx context.Context, agEvtID int64, evt AssociationEvent, now time.Time) error {
	return ap.rdb.Get().WithContext(ctx).Transaction(func(db *gorm.DB) error {
		for _, evt := range evt.GetEvents() {
			asso := new(model.PalaceEventSignalAssociation)
			asso.AggrEvtID = agEvtID
			asso.AggrKey = evt.AggregationKey()
			asso.SignalID = evt.ID()
			asso.CreatedAt = now
			_, err := dal.CreateSignalAssociation(ctx, db, asso)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("create signal association error", err)
			}
		}
		return nil
	})
}

func (ap *AssociationProcessor) createAssociationLinks(ctx context.Context, agEvtID int64, evt AssociationEvent, now time.Time) error {
	return ap.rdb.Get().WithContext(ctx).Transaction(func(db *gorm.DB) error {
		for _, link := range evt.GetAssociatedLinks() {
			linkModel := new(model.PalaceAssociationLink)
			linkModel.AggrEvtID = agEvtID
			linkModel.CreatedAt = now
			linkModel.SrcClusterKey = link.SrcLoc.ClusterKey()
			linkModel.SrcLocType = string(link.SrcLoc.Type())
			linkModel.SrcLocExpr = link.SrcLoc.String()
			linkModel.DestClusterKey = link.DestLoc.ClusterKey()
			linkModel.DestLocType = string(link.DestLoc.Type())
			linkModel.DestLocExpr = link.DestLoc.String()
			linkModel.CreatedAt = now

			_, err := dal.CreateAssociationLinks(ctx, db, linkModel)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("create association link error", err)
			}
		}
		return nil
	})
}

func (ap *AssociationProcessor) upsertAssociationGraphEvent(ctx context.Context, evt AssociationEvent) (int64, error) {
	now := time.Now()
	evtID, err := ap.createAGEvent(ctx, evt, now)
	if err != nil {
		return 0, err
	}
	tctx, cancel := context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()
	err = util.RetryWithBackoff(tctx, func() error {
		return ap.createSignalAssociations(tctx, evtID, evt, now)
	}, retry.Attempts(2))
	if err != nil {
		return 0, err
	}

	tctx, cancel = context.WithTimeout(ctx, 5000*time.Millisecond)
	defer cancel()
	err = util.RetryWithBackoff(tctx, func() error {
		return ap.createAssociationLinks(tctx, evtID, evt, now)
	}, retry.Attempts(2))

	return evtID, err
}

func (ap *AssociationProcessor) handleAssocatedEvent(ctx context.Context, evt AssociationEvent) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when handleAssocatedEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	evtID, err := ap.upsertAssociationGraphEvent(ctx, evt)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("upsert agraph event err. evt: %+v", evt)
		return err
	}
	evt.SetID(evtID)
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
		if now.Sub(aggr.updatedAt) >= ap.config.SubmitLatency {
			aggr.RequireStop()
			toClean[key] = struct{}{}
		}
	}

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
					logging.GetLogger().Err(err).Msgf("handle association event error. event: %+v", e)
				}
			case now := <-ticker.C:
				ap.cleanUp(now)
			}
		}
	}()
}

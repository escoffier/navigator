package palace

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	loadRulesInterval = 5 * time.Minute
)

var (
	instance *Service
	once     sync.Once
)

func Init(rdb *rdbtools.GormWrapper, esCli *elastic.Client) error {
	once.Do(func() {
		instance = newService(rdb, esCli)
	})
	return nil
}
func Get() (*Service, bool) {
	return instance, instance != nil
}

type Service struct {
	rdb          *rdbtools.GormWrapper
	elasticCli   *elastic.Client
	rulesManager *echelper.RulesManager
}

func newService(rdb *rdbtools.GormWrapper, esCli *elastic.Client) *Service {
	rm := echelper.NewRulesManager(rdb, loadRulesInterval)
	return &Service{rdb: rdb, elasticCli: esCli, rulesManager: rm}
}

func (s *Service) GetAssociatedEvents(ctx context.Context, offsetID int64, limit int) ([]*model.PalaceAssociatedGraphEvent, int64, error) {
	events, err := dal.GetAssociatedGraphEvents(ctx, s.rdb.Get(), offsetID, limit)
	if err != nil {
		return nil, 0, err
	}
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var totalCnt int64
	err = util.RetryWithBackoff(tctx, func() error {
		var err error
		totalCnt, err = dal.CountAssociatedGraphEvents(ctx, s.rdb.Get())
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return events, totalCnt, nil
}

func splitLocExpr(locExpr string) (clusterKey, namespace, podName, containerName string, pid int64, pname string, err error) {
	elems := strings.Split(locExpr, "/")
	if len(elems) != 5 {
		err = fmt.Errorf("decode loc expr %s error", locExpr)
		return
	}
	procArr := strings.Split(elems[4], "|")
	if len(procArr) != 2 {
		err = fmt.Errorf("process %s decode error", locExpr)
		return
	}
	pid, err = strconv.ParseInt(procArr[0], 10, 64)
	if err != nil {
		return
	}
	return elems[0], elems[1], elems[2], elems[3], pid, procArr[1], nil
}

func (s *Service) GetSignalsOfEvent(ctx context.Context, evtID int64, query *dal.SignalsQuery, offsetTime time.Time, limit int, language string) ([]*SignalElem, int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	totalCnt, err := dal.CountSignalsOfEvent(tctx, s.rdb.Get(), evtID, query)
	if err != nil {
		return nil, 0, err
	}
	if totalCnt == 0 {
		return nil, 0, nil
	}

	var signals []*model.PalaceEventSignalAssociation
	err = util.RetryWithBackoff(tctx, func() error {
		var err error
		signals, err = dal.GetOriginSignalsOfEvent(ctx, s.rdb.Get(), evtID, query, offsetTime, limit)
		return err
	})

	if err != nil {
		return nil, 0, err
	}
	if len(signals) == 0 {
		return nil, 0, nil
	}

	signalUUIDs := make([]string, len(signals))
	for i, signal := range signals {
		signalUUIDs[i] = signal.SignalID
	}
	signalsFinals, err := dal.GetSignals(tctx, s.elasticCli, signalUUIDs)

	signalElems := make([]*SignalElem, 0, len(signalsFinals))
	for _, signal := range signalsFinals {
		se := toApiSignal(signal, language)
		rule, _ := s.rulesManager.GetRule(signal.RuleModule, signal.RuleCategory, signal.RuleName)
		if rule != nil {
			se.Rule = toApiRule(rule, language)

		}
		signalElems = append(signalElems, se)
	}
	return signalElems, totalCnt, err
}

func (s *Service) GetProcessTree(ctx context.Context, evtID int64) (*TreeNode, error) {
	links, err := dal.GetAssociationLinksOfEvent(ctx, s.rdb.Get(), evtID)
	if err != nil {
		return nil, err
	}

	toParent := make(map[*TreeNode]*TreeNode, len(links)-1)
	nodes := make(map[string]*TreeNode, len(links))
	for _, link := range links {
		destKey := fmt.Sprintf("%s/%s", link.DestClusterKey, link.DestLocExpr)
		dest, destExist := nodes[destKey]
		if !destExist {
			_, destNs, destPodName, destCname, destPid, destPname, err := splitLocExpr(link.DestLocExpr)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("link %+v src decode err", link)
				continue
			}
			dest = &TreeNode{
				ClusterKey:    link.DestClusterKey,
				Namespace:     destNs,
				PodName:       destPodName,
				ContainerName: destCname,
				PID:           destPid,
				Pname:         destPname,
			}
			nodes[destKey] = dest
		}

		srcKey := fmt.Sprintf("%s/%s", link.SrcClusterKey, link.SrcLocExpr)
		src, srcExist := nodes[srcKey]
		if !srcExist {
			_, srcNs, srcPodName, srcCname, srcPid, srcPname, err := splitLocExpr(link.SrcLocExpr)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("link %+v src decode err", link)
				continue
			}
			src = &TreeNode{
				ClusterKey:    link.SrcClusterKey,
				Namespace:     srcNs,
				PodName:       srcPodName,
				ContainerName: srcCname,
				PID:           srcPid,
				Pname:         srcPname,
			}
			nodes[srcKey] = src
		}
		src.Children = append(src.Children, dest)
		toParent[dest] = src
	}
	var root *TreeNode
	for _, node := range nodes {
		if _, existParent := toParent[node]; !existParent {
			root = node
			break
		}
	}
	if root != nil {
		return root, nil
	} else {
		return nil, errors.New("cannot find the tree root")
	}
}

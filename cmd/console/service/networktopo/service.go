package networktopo

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
)

var (
	instance *NetworkTopoService
	once     sync.Once
)

const (
	cacheSize = 5 * 1024
	cacheTTL  = 10 * time.Minute
)

type NetProtocol = uint8

const (
	TCP NetProtocol = iota + 1
	UDP
)

func Init(postgresDB *rdbtools.GormWrapper) error {
	if postgresDB == nil {
		return errors.New("illegal argument")
	}
	once.Do(func() {
		instance = newNetworkTopoService(postgresDB)
	})
	return nil
}

func Get(ctx context.Context) (*NetworkTopoService, bool) {
	return instance, instance != nil
}

type NetworkTopoService struct {
	postgresDB *rdbtools.GormWrapper
	topoCache  *ttlcache.Cache
}

func newTopoCache() *ttlcache.Cache {
	cache := ttlcache.NewCache()
	cache.SetCacheSizeLimit(cacheSize)
	cache.SetTTL(cacheTTL)
	return cache
}
func newNetworkTopoService(postgresDB *rdbtools.GormWrapper) *NetworkTopoService {
	return &NetworkTopoService{
		postgresDB: postgresDB,
		topoCache:  newTopoCache(),
	}
}

func (n *NetworkTopoService) ListUpstreamInfo(ctx context.Context, scluster, sns, skind, sname string, qw int) ([]ResourceInfo, int64, error) {
	var tfs []*model.TensorNetworkFlow
	err := n.postgresDB.Get().WithContext(ctx).
		Where("updated_at > ?", time.Now().Add(-time.Duration(qw)*time.Hour)).
		Where("src_cluster = ?", scluster).
		Where("src_namespace = ?", sns).
		Where("src_kind = ?", skind).
		Where("src_name = ?", sname).
		Find(&tfs).Error
	if err != nil {
		return nil, 0, err
	}
	var res []ResourceInfo
	for _, t := range tfs {
		r := ResourceInfo{
			Cluster:   t.DstCluster,
			Namespace: t.DstNamespace,
			Kind:      t.DstKind,
			Resource:  t.DstName,
			Port:      t.DstPort,
		}
		switch t.Proto {
		case TCP:
			r.Protocol = "TCP"
		case UDP:
			r.Protocol = "UDP"
		}
		res = append(res, r)
	}
	return res, int64(len(res)), nil
}

func (n *NetworkTopoService) ListDownstreamInfo(ctx context.Context, dcluster, dns, dkind, dname string, qw int) ([]ResourceInfo, int64, error) {
	var tfs []*model.TensorNetworkFlow
	err := n.postgresDB.Get().WithContext(ctx).
		Where("updated_at > ?", time.Now().Add(-time.Duration(qw)*time.Hour)).
		Where("dst_cluster = ?", dcluster).
		Where("dst_namespace = ?", dns).
		Where("dst_kind = ?", dkind).
		Where("dst_name = ?", dname).
		Find(&tfs).Error
	if err != nil {
		return nil, 0, err
	}
	var res []ResourceInfo
	for _, t := range tfs {
		r := ResourceInfo{
			Cluster:   t.SrcCluster,
			Namespace: t.SrcNamespace,
			Kind:      t.SrcKind,
			Resource:  t.SrcName,
			Port:      t.DstPort,
		}
		switch t.Proto {
		case TCP:
			r.Protocol = "TCP"
		case UDP:
			r.Protocol = "UDP"
		}
		res = append(res, r)
	}
	return res, int64(len(res)), nil
}

func (n *NetworkTopoService) checkCache(flow *model.TensorNetworkFlow) bool {
	if n.topoCache == nil {
		return false
	}
	if flow.UUID == 0 {
		return false
	}
	_, err := n.topoCache.Get(strconv.FormatUint(uint64(flow.UUID), 10))
	return err == nil
}

func (n *NetworkTopoService) putToCache(flow *model.TensorNetworkFlow) error {
	if n.topoCache == nil {
		return nil
	}
	return n.topoCache.Set(strconv.FormatUint(uint64(flow.UUID), 10), struct{}{})
}

func (n *NetworkTopoService) addNetworkTopo(ctx context.Context, flow *model.TensorNetworkFlow, db *gorm.DB, t time.Time) error {
	if n.checkCache(flow) {
		return nil
	}
	if flow.CreatedAt.IsZero() {
		flow.CreatedAt = t
	}
	if flow.UpdatedAt.IsZero() {
		flow.UpdatedAt = t
	}

	err := dal.UpsertNetworkFlow(ctx, db, flow)

	return err
}
func (n *NetworkTopoService) AddNetTopology(ctx context.Context, flow *model.TensorNetworkFlow) error {
	ctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	err := util.RetryWithBackoff(ctx, func() error {
		return n.addNetworkTopo(ctx, flow, n.postgresDB.Get(), time.Now())
	})
	if err == nil {
		n.putToCache(flow)
	}
	return err
}

func (n *NetworkTopoService) AddNetTopologies(ctx context.Context, flows []*model.TensorNetworkFlow) error {
	now := time.Now()
	okFlows := make([]*model.TensorNetworkFlow, 0, len(flows))
	txErr := n.postgresDB.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, flow := range flows {
			if err := n.addNetworkTopo(ctx, flow, tx, now); err == nil {
				okFlows = append(okFlows, flow)
			}
		}
		return nil
	})
	if txErr == nil {
		for _, flow := range okFlows {
			n.putToCache(flow)
		}
	}
	return txErr
}

func (n *NetworkTopoService) ListNetTopologies(ctx context.Context, t time.Time) (nts []*model.TensorNetworkFlow, totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		oneErr := n.postgresDB.Get().WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Where("updated_at < ?", t).Find(&nts).Error
		if oneErr != nil {
			return oneErr
		}
		return n.postgresDB.Get().WithContext(ctx).Model(&model.TensorNetworkFlow{}).Where("updated_at < ?", t).Count(&totalCnt).Error
	})
	return
}

func (n NetworkTopoService) CountNetTopology(ctx context.Context, uuid uint32) (totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return n.postgresDB.Get().WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Where("uuid = ?", uuid).Count(&totalCnt).Error
	})
	return
}

func (n *NetworkTopoService) UpdateStatus(ctx context.Context, t time.Time, status int) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return n.postgresDB.Get().WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Where("updated_at < ?", t).Update("status", status).Error
	})
	return
}

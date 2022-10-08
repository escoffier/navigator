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
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
)

var (
	instance *Service
	once     sync.Once
)

const (
	cacheSize = 64 * 1024
	cacheTTL  = 60 * time.Minute
)

type NetProtocol = uint8

const (
	TCP NetProtocol = iota + 1
	UDP
)

func Init(rdb *databases.RDBInstance) error {
	if rdb == nil {
		return errors.New("illegal argument")
	}
	once.Do(func() {
		instance = newNetworkTopoService(rdb)
	})
	return nil
}

func Get(ctx context.Context) (*Service, bool) {
	return instance, instance != nil
}

type Service struct {
	rdb       *databases.RDBInstance
	topoCache *ttlcache.Cache
}

func newTopoCache() *ttlcache.Cache {
	cache := ttlcache.NewCache()
	cache.SetCacheSizeLimit(cacheSize)
	err := cache.SetTTL(cacheTTL)
	if err != nil {
		logging.Get().Error().Msgf("set ttl error, %v", err)
	}
	return cache
}
func newNetworkTopoService(rdb *databases.RDBInstance) *Service {
	return &Service{
		rdb:       rdb,
		topoCache: newTopoCache(),
	}
}

func (n *Service) ListUpstreamInfo(ctx context.Context, scluster, sns, skind, sname string, qw int) ([]ResourceInfo, int64, error) {
	var tfs []*model.TensorNetworkFlow
	err := n.rdb.GetReadDB().WithContext(ctx).
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
			Resource:  t.DstOwnerName,
			Port:      int(t.DstPort),
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

func (n *Service) ListDownstreamInfo(ctx context.Context, dcluster, dns, dkind, dname string, qw int) ([]ResourceInfo, int64, error) {
	var tfs []*model.TensorNetworkFlow
	err := n.rdb.GetReadDB().WithContext(ctx).
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
			Resource:  t.SrcOwnerName,
			Port:      int(t.DstPort),
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

func (n *Service) checkCache(flow *model.TensorNetworkFlow) bool {
	if n.topoCache == nil {
		return false
	}
	if flow.UUID == 0 {
		return false
	}
	_, err := n.topoCache.Get(strconv.FormatUint(uint64(flow.UUID), 10))
	return err == nil
}

func (n *Service) putToCache(flow *model.TensorNetworkFlow) error {
	if n.topoCache == nil {
		return nil
	}
	return n.topoCache.Set(strconv.FormatUint(uint64(flow.UUID), 10), struct{}{})
}

func (n *Service) addNetworkTopo(ctx context.Context, flow *model.TensorNetworkFlow, db *gorm.DB, t time.Time) error {
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
func (n *Service) AddNetTopology(ctx context.Context, flow *model.TensorNetworkFlow) error {
	if flow == nil {
		return errors.New("nil")
	}

	ctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	err := util.RetryWithBackoff(ctx, func() error {
		return n.addNetworkTopo(ctx, flow, n.rdb.Get(), time.Now())
	})
	if err == nil {
		err = n.putToCache(flow)
	}
	return err
}

func (n *Service) AddNetTopologies(ctx context.Context, flows []*model.TensorNetworkFlow) error {
	var eErr error
	for _, flow := range flows {
		err := n.AddNetTopology(ctx, flow)
		if err != nil {
			logging.Get().Err(err).Msgf("insert flow error. flow: %+v", flow)
			eErr = err
		}
	}
	return eErr
}

func (n *Service) ListNetTopologies(ctx context.Context, t time.Time) (nts []*model.TensorNetworkFlow, totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		oneErr := n.rdb.GetReadDB().WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Where("updated_at < ?", t).Find(&nts).Error
		if oneErr != nil {
			return oneErr
		}
		return n.rdb.GetReadDB().WithContext(ctx).Model(&model.TensorNetworkFlow{}).Where("updated_at < ?", t).Count(&totalCnt).Error
	})
	return
}

func (n Service) CountNetTopology(ctx context.Context, uuid uint32) (totalCnt int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err = util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return n.rdb.GetReadDB().WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Where("uuid = ?", uuid).Count(&totalCnt).Error
	})
	return
}

package networktopo

import (
	"context"
	"errors"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm/clause"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	instance *NetworkTopoService
	once     sync.Once
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
}

func newNetworkTopoService(postgresDB *rdbtools.GormWrapper) *NetworkTopoService {
	return &NetworkTopoService{
		postgresDB: postgresDB,
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

func (n *NetworkTopoService) AddNetTopology(ctx context.Context, flow *model.TensorNetworkFlow) error {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	flow.CreatedAt = time.Now()
	flow.UpdatedAt = flow.CreatedAt

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return n.postgresDB.Get().WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "uuid"}},
			DoNothing: true,
		}).Create(flow).Error
	})
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

func (n *NetworkTopoService) UpdateActiveTime(ctx context.Context, uuid uint32) error {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()

		return n.postgresDB.Get().WithContext(oneCtx).Model(&model.TensorNetworkFlow{}).Where("uuid = ?", uuid).Updates(map[string]interface{}{
			"status":     1,
			"updated_at": time.Now(),
		}).Error
	})
	return err
}

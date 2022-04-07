package scap

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Job struct {
	scap.Job
	UserName string
	Type     uint8
}

func (s *Service) CreateJob(ctx context.Context, job *Job) error {
	// 校验policy是否存在
	if err := s.rdb.Get().WithContext(ctx).Where("type = ?", job.Type).First(&model.ScapPolicy{}, job.PolicyID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("policy <%d> not found", job.PolicyID)
		}

		return fmt.Errorf("policy <%d> verify failed", job.PolicyID)
	}

	clusters := make([]model.ScapClusterInfo, 0, len(job.ClusterInfos))

	for _, v := range job.ClusterInfos {
		clusters = append(clusters, model.ScapClusterInfo{
			IsAllNodes:     v.IsAllNodes,
			ClusterKey:     v.ClusterKey,
			ClusterNodeIds: v.Nodes,
		})
	}

	if err := s.rdb.Get().WithContext(ctx).Create(clusters).Error; err != nil {
		logging.GetLogger().Err(err).Msg("创建集群信息失败")
		return errors.New("启动任务失败")
	}

	return s.Do(ctx, job, clusters)
}

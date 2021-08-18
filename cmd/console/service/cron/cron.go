package cron

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	cr "github.com/robfig/cron/v3"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	instance *CronService
	once     sync.Once
)

func Init(cron *cr.Cron, mongodb *mongotools.DatabaseWrapper, rootCtx context.Context) error {
	if cron == nil || mongodb == nil || rootCtx == nil {
		return errors.New("illegal argument")
	}
	once.Do(func() {
		instance = newCronService(cron, mongodb, rootCtx)
	})
	return nil
}

func Get(ctx context.Context) (*CronService, bool) {
	return instance, instance != nil
}

const (
	clusterCol = "cluster"
)

type CronService struct {
	cron    *cr.Cron
	mongodb *mongotools.DatabaseWrapper
	rootCtx context.Context
}

func newCronService(
	cron *cr.Cron,
	mongodb *mongotools.DatabaseWrapper,
	rootCtx context.Context,
) *CronService {
	return &CronService{
		cron:    cron,
		mongodb: mongodb,
		rootCtx: rootCtx,
	}
}

func (s *CronService) updateCronExecTimes(ctx context.Context, clusterObjectID primitive.ObjectID, checkType model.ComplianceCheckType, next *time.Time, prev *time.Time) error {
	clusterSvc, _ := cluster.Get(ctx)
	cluster, err := clusterSvc.GetCluster(ctx, clusterObjectID, false)
	if err != nil {
		return err
	}

	if checkType == model.ComplianceCheckTargetTypeKube {
		cluster.CronConfig.KubeBenchCron.NextRun = next
		cluster.CronConfig.KubeBenchCron.PrevRun = prev
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		cluster.CronConfig.DockerBenchCron.NextRun = next
		cluster.CronConfig.DockerBenchCron.PrevRun = prev
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		cluster.CronConfig.HostBenchCron.NextRun = next
		cluster.CronConfig.HostBenchCron.PrevRun = prev
	}

	filter := bson.M{"_id": clusterObjectID, "deleted_at": bson.M{"$exists": false}}
	cluster.ID = clusterObjectID
	update := bson.M{"$set": cluster}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*1)
	defer mongoCtxCancel()
	_, err = s.mongodb.Get().Collection(clusterCol).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

func (s *CronService) startCron(ctx context.Context, cluster *model.Cluster, checkType model.ComplianceCheckType) error {
	logging.GetLogger().Info().
		Str("cluster", fmt.Sprintf("%+v", cluster.ClusterName)).
		Str("checkType", fmt.Sprintf("%s", checkType)).
		Msg("Registering compliance cron")

	var cronID int
	var cronString string
	if checkType == model.ComplianceCheckTargetTypeKube {
		cronID = cluster.CronConfig.KubeBenchCron.CronID
		cronString = cluster.CronConfig.KubeBenchCron.CronString
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		cronID = cluster.CronConfig.DockerBenchCron.CronID
		cronString = cluster.CronConfig.DockerBenchCron.CronString
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		cronID = cluster.CronConfig.HostBenchCron.CronID
		cronString = cluster.CronConfig.HostBenchCron.CronString
	}
	if cronID != 0 {
		if s.idInCronEntries(cronID, s.cron.Entries()) {
			s.cron.Remove(cr.EntryID(cronID))
		}
		if checkType == model.ComplianceCheckTargetTypeKube {
			cluster.CronConfig.KubeBenchCron.CronID = 0
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			cluster.CronConfig.DockerBenchCron.CronID = 0
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			cluster.CronConfig.HostBenchCron.CronID = 0
		}
	}
	if cronString != "" {
		newCronID, err := s.cron.AddFunc(cronString, func() {
			logging.GetLogger().Info().
				Str("cluster.CronConfig", fmt.Sprintf("%+v", cluster.CronConfig)).
				Str("checkType", fmt.Sprintf("%s", checkType)).
				Msg("Starting compliance cron job now")

			// don't cancel() when exiting this function as we are starting an async task
			newCtx, _ := context.WithTimeout(s.rootCtx, time.Minute*10)
			scapper, _ := scapper.GetScapper(ctx)
			_, err := scapper.RunComplianceCheck(newCtx, ctx, cluster, checkType, "system")
			if err != nil {
				logging.GetLogger().Error().Err(err).
					Str("cluster.CronConfig", fmt.Sprintf("%+v", cluster.CronConfig)).
					Str("checkType", fmt.Sprintf("%s", checkType)).
					Msg("Failed to run compliance check")
			} else {
				logging.GetLogger().Info().
					Str("cluster.CronConfig", fmt.Sprintf("%+v", cluster.CronConfig)).
					Str("checkType", fmt.Sprintf("%s", checkType)).
					Msg("Compliance cron job scheduled successfully")
			}

			// TODO: I though that here next and prev times can be updated via channels to spawned goroutines
			// responsible for updating times in DB. Problem is, that those fields in cron.Entry
			// are updated after the job is run, so there might be a race condition here
			// https://github.com/robfig/cron/blob/master/cron.go#L273
		})
		// TODO: maybe retry on error?
		if err != nil {
			return NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't schedule job: %w", err), Suberror{"cronString", err.Error()})
		}
		if checkType == model.ComplianceCheckTargetTypeKube {
			cluster.CronConfig.KubeBenchCron.CronID = int(newCronID)
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			cluster.CronConfig.DockerBenchCron.CronID = int(newCronID)
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			cluster.CronConfig.HostBenchCron.CronID = int(newCronID)
		}
	}
	filter := bson.M{"_id": cluster.ID, "deleted_at": bson.M{"$exists": false}}
	update := bson.M{"$set": cluster}
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*1)
	defer mongoCtxCancel()
	_, err := s.mongodb.Get().Collection(clusterCol).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

func (s *CronService) StartCrons(ctx context.Context) error {
	clusterSvc, _ := cluster.Get(ctx)
	clusters, _, err := clusterSvc.ListClusters(ctx, 0, math.MaxInt64)
	if err != nil {
		return err
	}
	for _, cluster := range clusters {
		for _, checkType := range []model.ComplianceCheckType{
			model.ComplianceCheckTargetTypeKube,
			model.ComplianceCheckTargetTypeDocker,
			model.ComplianceCheckTargetTypeHost} {
			err = s.startCron(ctx, &cluster, checkType)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *CronService) idInCronEntries(ID int, cronEntries []cr.Entry) bool {
	for _, entry := range cronEntries {
		if ID == int(entry.ID) {
			return true
		}
	}
	return false
}

func (s *CronService) UpdateCron(ctx context.Context, clusterObjectID primitive.ObjectID, checkType model.ComplianceCheckType, cronString string) error {
	// get kube client for this cluster
	mongoGetCtx, mongoGetCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoGetCtxCancel()

	clusterSvc, _ := cluster.Get(ctx)
	cluster, err := clusterSvc.GetCluster(mongoGetCtx, clusterObjectID, false)
	if err != nil {
		return err
	}

	if checkType == model.ComplianceCheckTargetTypeKube {
		cluster.CronConfig.KubeBenchCron.CronString = cronString
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		cluster.CronConfig.DockerBenchCron.CronString = cronString
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		cluster.CronConfig.HostBenchCron.CronString = cronString
	}

	filter := bson.M{"deleted_at": bson.M{"$exists": false}, "_id": clusterObjectID}
	cluster.ID = clusterObjectID
	update := bson.M{"$set": cluster}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*1)
	defer mongoCtxCancel()
	_, err = s.mongodb.Get().Collection(clusterCol).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		return err
	}

	clusterGetCtx, clusterGetCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer clusterGetCtxCancel()
	cluster, err = clusterSvc.GetCluster(clusterGetCtx, clusterObjectID, false)
	if err != nil {
		return err
	}

	err = s.startCron(ctx, cluster, checkType)
	if err != nil {
		return err
	}

	return nil
}

func (s *CronService) GetCron(ctx context.Context, clusterObjectID primitive.ObjectID, checkType model.ComplianceCheckType) (string, error) {
	// get kube client for this cluster
	clusterSvc, _ := cluster.Get(ctx)
	cluster, err := clusterSvc.GetCluster(ctx, clusterObjectID, false)
	if err != nil {
		return "", err
	}

	var cronString string
	if checkType == model.ComplianceCheckTargetTypeKube {
		cronString = cluster.CronConfig.KubeBenchCron.CronString
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		cronString = cluster.CronConfig.DockerBenchCron.CronString
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		cronString = cluster.CronConfig.HostBenchCron.CronString
	}
	return cronString, nil
}

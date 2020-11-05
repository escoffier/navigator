package cron

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	cr "github.com/robfig/cron/v3"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	clusterCol = "cluster"
)

type CronService struct {
	cron           *cr.Cron
	mongodb        *mongo.Database
	scapper        *scapper.Scapper
	clusterService *cluster.ClusterService
	rootCtx        context.Context
}

func NewCronService(
	cron *cr.Cron,
	mongodb *mongo.Database,
	scapper *scapper.Scapper,
	clusterService *cluster.ClusterService,
	rootCtx context.Context,
) *CronService {
	return &CronService{
		cron:           cron,
		mongodb:        mongodb,
		scapper:        scapper,
		clusterService: clusterService,
		rootCtx:        rootCtx,
	}
}

func (s *CronService) updateCronExecTimes(ctx context.Context, clusterObjectID primitive.ObjectID, checkType string, next *time.Time, prev *time.Time) error {
	cluster, err := s.clusterService.GetCluster(ctx, clusterObjectID)
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

	filter := bson.M{"_id": clusterObjectID}
	cluster.ID = clusterObjectID
	update := bson.M{"$set": cluster}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	_, err = s.mongodb.Collection(clusterCol).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

func (s *CronService) startCron(ctx context.Context, cluster *model.Cluster, checkType string) error {
	logging.GetLogger().Info().
		Str("cluster", fmt.Sprintf("%+v", cluster)).
		Str("checkType", checkType).
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
				Str("checkType", checkType).
				Msg("Starting compliance cron job now")

			newCtx, newCtxCancel := context.WithTimeout(s.rootCtx, time.Minute*10)
			defer newCtxCancel()
			_, err := s.scapper.RunComplianceCheck(newCtx, ctx, cluster.ID, cluster, checkType)
			if err != nil {
				logging.GetLogger().Error().Err(err).
					Str("cluster.CronConfig", fmt.Sprintf("%+v", cluster.CronConfig)).
					Str("checkType", checkType).
					Msg("Failed to run compliance check")
			} else {
				logging.GetLogger().Info().
					Str("cluster.CronConfig", fmt.Sprintf("%+v", cluster.CronConfig)).
					Str("checkType", checkType).
					Msg("Compliance cron job finished successfully")
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
	filter := bson.M{"_id": cluster.ID}
	update := bson.M{"$set": cluster}
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	_, err := s.mongodb.Collection(clusterCol).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

func (s *CronService) StartCrons(ctx context.Context) error {
	clusters, _, err := s.clusterService.ListClusters(ctx, 0, math.MaxInt64)
	if err != nil {
		return err
	}
	for _, cluster := range clusters {
		for _, checkType := range []string{model.ComplianceCheckTargetTypeKube,
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

func (s *CronService) UpdateCron(ctx context.Context, clusterObjectID primitive.ObjectID, checkType string, cronString string) error {
	// get kube client for this cluster
	mongoGetCtx, mongoGetCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoGetCtxCancel()
	cluster, err := s.clusterService.GetCluster(mongoGetCtx, clusterObjectID)
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

	filter := bson.M{"_id": clusterObjectID}
	cluster.ID = clusterObjectID
	update := bson.M{"$set": cluster}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	_, err = s.mongodb.Collection(clusterCol).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		return err
	}

	clusterGetCtx, clusterGetCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer clusterGetCtxCancel()
	cluster, err = s.clusterService.GetCluster(clusterGetCtx, clusterObjectID)
	if err != nil {
		return err
	}

	err = s.startCron(ctx, cluster, checkType)
	if err != nil {
		return err
	}

	return nil
}

func (s *CronService) GetCron(ctx context.Context, clusterObjectID primitive.ObjectID, checkType string) (string, error) {
	// get kube client for this cluster
	cluster, err := s.clusterService.GetCluster(ctx, clusterObjectID)
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

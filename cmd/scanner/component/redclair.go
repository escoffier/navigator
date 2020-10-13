package component

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

const (
	scanOneTimeout = time.Minute * 5
)

// RedClair ...
type RedClairService struct {
	ctx     context.Context
	mongodb *mongo.Database

	scanTasksChan chan model.ScanTask

	redclairEngine *redclair.Redclair
}

// NewRedClair creates the instance of RedClair
func NewRedClairService(ctx context.Context, clairOpts *flag.ClairOpts, db *mongo.Database) (*RedClairService, error) {
	redclairEng, err := redclair.NewRedclair(clairOpts)
	if err != nil {
		return nil, err
	}
	return &RedClairService{
		ctx:            ctx,
		mongodb:        db,
		scanTasksChan:  make(chan model.ScanTask, 1000),
		redclairEngine: redclairEng,
	}, nil
}

// Run runs the RedClair instance
func (rcSvc *RedClairService) Run(ctx context.Context) {

	// Set scanner environment
	err := os.Setenv("DOCKER_API_VERSION", "1.38")
	if err != nil {
		log.Panic().Err(err).Msg("error in setting DOCKER_API_VERSION")
	}

	err = rcSvc.redclairEngine.StartImageHTTPServer()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to start image http server")
	}
	defer rcSvc.redclairEngine.StopImageHTTPServer()

	// TODO do we want some max num of workers?
loop:
	for {
		select {
		case scanTask := <-rcSvc.scanTasksChan:
			go rcSvc.asyncProcessScanTask(ctx, scanTask)
		case <-ctx.Done():
			break loop
		}
	}
}

func (rcSvc *RedClairService) asyncProcessScanTask(ctx context.Context, scanTask model.ScanTask) {
	scanCtx, scanCtxCancel := context.WithTimeout(ctx, scanOneTimeout)
	defer scanCtxCancel()

	scanDoneCh := make(chan struct{})
	go func() {
		vulnReport, fileSignatures, software, err := rcSvc.redclairEngine.Scan(
			scanCtx,
			redclair.ScannerConfig{
				Repository:         scanTask.Repository,
				ImageName:          scanTask.GetNameTag(),
				WhitelistThreshold: "Unknown",
				ReportAll:          true,
			},
		)

		if err != nil {
			log.Error().Err(err).Msg("Redclair scan failed")

			scanTask.FinishedAt = time.Now().Unix()
			scanTask.Status = model.ScanStatusFailed
			scanTask.Message = err.Error()

			rcSvc.updateMongoStatus(ctx, scanTask)
		} else {
			scanTask.FinishedAt = time.Now().Unix()
			scanTask.Status = model.ScanStatusSucceeded
			scanTask.ScanReport = model.ScanReport{
				Vulns:    *vulnReport,
				Files:    fileSignatures,
				Software: software,
			}

			rcSvc.updateMongoStatus(ctx, scanTask)
		}

		scanDoneCh <- struct{}{}
	}()

	select {
	case <-scanDoneCh:
		log.Info().Msg("Redclair scan succeeded")
		break
	case <-scanCtx.Done():
		log.Error().Err(ctx.Err()).Msg("Redclair scan timeout")

		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusFailed
		scanTask.Message = ctx.Err().Error()

		rcSvc.updateMongoStatus(ctx, scanTask)
	}
}

// AddScanTask adds ScanTask to the internal channel
func (rcSvc *RedClairService) AddScanTask(task model.ScanTask) {
	rcSvc.scanTasksChan <- task
}

func (rcSvc *RedClairService) updateMongoStatus(ctx context.Context, scanTask model.ScanTask) {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	filter := bson.M{"_id": scanTask.ID}
	update := bson.M{"$set": scanTask}

	_, err := rcSvc.mongodb.Collection(model.ScanTasksCollection).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		log.Error().
			Err(err).
			Str("scanTask", fmt.Sprintf("%+v", scanTask)).
			Msg("error in updating task in Mongo")
	}
}

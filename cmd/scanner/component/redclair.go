package component

import (
	"context"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
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

	// we can have multiple workers here
loop:
	for {
		select {
		case scanTask := <-rcSvc.scanTasksChan:
			// TODO: currently this is blocking...
			rcSvc.processScanTask(scanTask)
		case <-ctx.Done():
			break loop
		}
	}
}

func (rcSvc *RedClairService) processScanTask(scanTask model.ScanTask) {
	// If scanTask.ForceScan

	// handle scanTask here
	vulnReport, fileSignatures, software, err := rcSvc.redclairEngine.Scan(
		redclair.ScannerConfig{
			ImageName:          scanTask.GetNameTag(),
			WhitelistThreshold: "Unknown",
			ReportAll:          true,
		},
	)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in redclair.Scan()")
	}

	scanTask.ScanReport = model.ScanReport{
		Vulns:    *vulnReport,
		Files:    fileSignatures,
		Software: software,
	}

	filter := bson.M{"_id": scanTask.ID}
	update := bson.M{"$set": scanTask}

	ctx, cancel := context.WithTimeout(rcSvc.ctx, 10*time.Second)
	defer cancel()
	_, err = rcSvc.mongodb.Collection(model.ScanTasksCollection).UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in updating task in Mongo")
	}
}

// AddScanTask adds ScanTask to the internal channel
func (rcSvc *RedClairService) AddScanTask(task model.ScanTask) {
	rcSvc.scanTasksChan <- task
}

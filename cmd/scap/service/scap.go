package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/scap"
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
}

// Run is to run the service.
func Run(name string, conf model.CheckerConfig, cmd *cobra.Command) {
	mongoOpts := flag.GetMongoOpts(cmd)
	// mongo client
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(fmt.Sprintf(
		"mongodb://%s:%s@%s", mongoOpts.Username, mongoOpts.Password, mongoOpts.Endpoint)))
	if err != nil {
		log.Error().Msgf("Error: %v", err)
		return
	}

	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	ctx, cancel := context.WithTimeout(mainCtx, 10*time.Second)
	defer cancel()
	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in connecting to the Mongo database")
		return
	}

	mongodb := mongoClient.Database(mongoOpts.Database)

	c, err := scap.GetChecker(name)
	if err != nil {
		log.Error().Msgf("Failed to get the checker: %v", err)
		return
	}

	done := lifecycle.ListenToSignals()
	processSingleScapTask(mainCtx, c, conf, mongodb, name)
loop:
	for {
		select {
		case <-time.After(30 * time.Second):
			processSingleScapTask(mainCtx, c, conf, mongodb, name)
		case <-done:
			break loop
		}
	}
}

func processSingleScapTask(
	mainCtx context.Context,
	c scap.Checker,
	conf model.CheckerConfig,
	mongodb *mongo.Database,
	name string,
) {
	ctx, cancel := context.WithTimeout(mainCtx, 10*time.Second)

	// from Mongo
	opts := options.FindOne()
	opts.SetSort(bson.D{{Key: "created_at", Value: 1}})

	var task model.ScapTask
	err := mongodb.Collection(model.ScapTasksCollection).FindOne(
		ctx,
		bson.M{
			"scanner_type":   name,
			"scanner_status": model.ScannerStatusReady,
		},
		opts,
	).Decode(&task)
	cancel()
	if err != nil {
		if !strings.Contains(err.Error(), "no documents in result") {
			log.Error().Msgf("mongo FindOne failed: %v\n", err)
		}
		return
	}

	task.Config = conf
	log.Info().Msgf("%+v", task)

	err = c.InitializeChecker(&task)
	if err != nil {
		log.Error().Msgf("Initialization failed: %v\n", err)
		return
	}

	log.Info().Msgf("Starting %s Checker...", name)

	checkResult, err := c.Check()
	if err != nil {
		log.Error().Msgf("Error %v\n", err)
		task.Status = model.ScannerStatusFailed
	} else {
		task.Status = model.ScannerStatusCompleted
	}
	checkResultBytes, err := json.Marshal(checkResult)
	if err != nil {
		log.Error().Msgf("Error in JSON marshalling %v\n", err)
		task.Status = model.ScannerStatusFailed
	} else {
		task.Result = string(checkResultBytes)
	}

	// save to Mongo
	filter := bson.M{"_id": task.ID}
	update := bson.M{"$set": task}
	ctx, cancel = context.WithTimeout(mainCtx, 10*time.Second)
	defer cancel()
	_, err = mongodb.Collection(model.ScapTasksCollection).UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in updating task in Mongo")
	}
	log.Info().Msgf("Saved task %s", task.ID)
}

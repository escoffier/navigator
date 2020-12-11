package service

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.etcd.io/etcd/clientv3"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
}

// Scanner represents the Vegeta Scanner server.
type Scanner struct {
	lifecycle.Service
	server      *http.Server
	etcd        *clientv3.Client
	redclair    *component.RedClairService
	mongoClient *mongo.Client
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewScanner is to create a new Scanner struct.
func NewScanner(
	httpOpts *flag.HTTPOpts,
	mongoOpts *flag.MongoOpts,
	clairOpts *flag.ClairOpts,
	redisOpts *flag.RedisOpts,
	updateOpts *flag.UpdateOpts,
) (*Scanner, error) {
	// mongo client
	// TODO: authSource database should be a separate argument.
	mongoString := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=%s", mongoOpts.Username, mongoOpts.Password, mongoOpts.Endpoint, mongoOpts.Database)
	mongoClientOptions := options.Client().ApplyURI(mongoString)
	mongoClientOptions.SetWriteConcern(writeconcern.New(writeconcern.WMajority()))
	mongoClientOptions.SetReadConcern(readconcern.Majority())
	mongoClient, err := mongo.NewClient(mongoClientOptions)

	if err != nil {
		return nil, err
	}
	// connect the mongo client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in connecting to the Mongo database")
		panic(err)
	}

	mongodb := mongoClient.Database(mongoOpts.Database)

	// Redis DB client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisOpts.Endpoint,
		Password: redisOpts.Password,
		DB:       0, // TODO: Add DB
	})

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// redclair
	redclairSvc, err := component.NewRedClairService(mainCtx, clairOpts, mongodb, redisClient, updateOpts)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		server: &http.Server{
			Addr:    httpOpts.HTTPListen,
			Handler: setupChiRouter(mainCtx, redclairSvc, mongodb, httpOpts.HTTPLoggerDisabled),
		},
		redclair:    redclairSvc,
		mongoClient: mongoClient,
		ctx:         mainCtx,
		cancel:      mainCancel,
	}, nil
}

// Run is to run the service.
func (s *Scanner) Run() func() {
	log.Info().Msg("Vegeta Scanner started")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Panic().
					Err(err).
					Msg("Panic in http.Server.ListenAndServe")
			}
		}
	}()

	// start clair scanner
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.redclair.Run(s.ctx)
		if err != nil {
			log.Panic().
				Err(err).
				Msg("Panic failed to start redclair")
		}
	}()

	return func() {
		s.cancel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			log.Error().
				Err(err).
				Msg("error in shutting down HTTP server")
		}
		wg.Wait()

		log.Info().Msg("Vegeta Scanner stopped")
	}
}

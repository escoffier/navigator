package service

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	cr "github.com/robfig/cron/v3"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
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

// Console represents the Vegeta Console server.
type Console struct {
	lifecycle.Service
	server      *http.Server
	mongoClient *mongo.Client
	cronService *cron.CronService
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewConsole is to create a new Console struct.
func NewConsole(
	httpOpts *flag.HTTPOpts,
	mongoOpts *flag.MongoOpts,
	scannerOpts *flag.VegetaScannerOpts,
	scapOpts *flag.ScapOpts,
) (*Console, error) {
	// mongo client
	// TODO: authSource database should be a separate argument.
	mongoString := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=%s", mongoOpts.Username, mongoOpts.Password, mongoOpts.Endpoint, mongoOpts.Database)
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(mongoString))
	if err != nil {
		return nil, err
	}

	mongodb := mongoClient.Database(mongoOpts.Database)

	// cluster service
	clusterService := cluster.NewClusterService(mongodb)

	// scap service
	scapper := &scapper.Scapper{
		DockerRepoHostPort: scapOpts.HostPort,
		MongoDB:            mongodb,
		MongoEndpoint:      mongoOpts.Endpoint,
		MongoUsername:      mongoOpts.Username,
		MongoPassword:      mongoOpts.Password,
		MongoDatabase:      mongoOpts.Database,
		MongoSecretName:    mongoOpts.SecretName,
	}

	// cron service
	c := cr.New()
	c.Start()
	cronService := cron.NewCronService(c, mongodb, scapper, clusterService)

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	return &Console{
		server: &http.Server{
			Addr: httpOpts.HTTPListen,
			Handler: setupChiRouter(
				mainCtx,
				mongodb,
				scapper,
				fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port),
				httpOpts.HTTPLoggerDisabled,
				cronService,
				clusterService,
			),
		},
		mongoClient: mongoClient,
		cronService: cronService,
		ctx:         mainCtx,
		cancel:      mainCancel,
	}, nil
}

// Run is to run the service.
func (c *Console) Run() func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Error().
					Err(err).
					Msg("error in http.Server.ListenAndServe")
			}
		}
	}()

	// connect the mongo client
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	err := c.mongoClient.Connect(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in connecting to the Mongo database")
		panic(err)
	}

	err = c.cronService.StartCrons(c.ctx)
	if err != nil {
		log.Error().Err(err).Msg("error starting cron jobs")
		panic(err)
	}

	log.Info().Msg("Vegeta Console started")

	return func() {
		c.cancel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.server.Shutdown(ctx); err != nil {
			log.Error().
				Err(err).
				Msg("error in shutting down HTTP server")
		}
		wg.Wait()

		log.Info().Msg("Vegeta Console stopped")
	}
}

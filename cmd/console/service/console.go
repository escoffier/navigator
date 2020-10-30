package service

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	cr "github.com/robfig/cron/v3"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/onlinevulns"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
	server             *http.Server
	mongoClient        *mongo.Client
	mongodb            *mongo.Database
	cronService        *cron.CronService
	clusterService     *cluster.ClusterService
	onlineVulnsService *onlinevulns.OnlineVulnsService
	ctx                context.Context
	cancel             context.CancelFunc
}

// NewConsole is to create a new Console struct.
func NewConsole(
	httpOpts *flag.HTTPOpts,
	mongoOpts *flag.MongoOpts,
	scannerOpts *flag.VegetaScannerOpts,
	scapOpts *flag.ScapOpts,
	redisOpts *flag.RedisOpts,
	elasticOpts *flag.ElasticOpts,
	rulesOpts *flag.RulesOpts,
) (*Console, error) {
	// mongo client
	// TODO: authSource database should be a separate argument.
	mongoString := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=%s", mongoOpts.Username, mongoOpts.Password, mongoOpts.Endpoint, mongoOpts.Database)
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(mongoString))
	if err != nil {
		return nil, err
	}

	mongodb := mongoClient.Database(mongoOpts.Database)

	// Redis DB client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisOpts.Endpoint,
		Password: "", // TODO: Add authorization
		DB:       0,  // TODO: Add DB
	})

	onlineVulnsSvc := onlinevulns.NewOnlineVulnsService(mongodb)

	// cluster service
	clusterService := cluster.NewClusterService(mongodb, onlineVulnsSvc)

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

	ruleService := rule.NewRuleService(rulesOpts.AvailableRulesFolder, mongodb)

	es, err := elastic.NewClient(
		elastic.SetURL(fmt.Sprintf("http://%s:%s", elasticOpts.Host, elasticOpts.Port)),
		elastic.SetBasicAuth(elasticOpts.Username, elasticOpts.Password),
	)
	if err != nil {
		return nil, err
	}

	alertService := alert.NewAlertService(mainCtx, ruleService, es, elasticOpts.Index, mongodb)

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
				redisClient,
				ruleService,
				alertService,
				onlineVulnsSvc,
			),
		},
		mongoClient:        mongoClient,
		mongodb:            mongodb,
		cronService:        cronService,
		ctx:                mainCtx,
		cancel:             mainCancel,
		clusterService:     clusterService,
		onlineVulnsService: onlineVulnsSvc,
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

	// ctx for initialization steps
	ctx, cancel := context.WithTimeout(c.ctx, 60*time.Second)

	// connect the mongo client
	defer cancel()
	err := c.mongoClient.Connect(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When in connecting to Mongo database")
		panic(fmt.Errorf("When connecting to Mongo database: %w", err))
	}

	err = createMongoIndices(ctx, c.mongodb)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When creating mongo indices")
		panic(fmt.Errorf("When creating mongo indices: %w", err))
	}

	err = initializeOnlineVulnsWatch(ctx, c.clusterService, c.onlineVulnsService)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When initializing online vulns watch")
		panic(fmt.Errorf("When initializing online vulns watch: %w", err))
	}

	err = c.cronService.StartCrons(ctx)
	if err != nil {
		log.Error().Err(err).Msg("When starting cron jobs")
		panic(fmt.Errorf("When starting cron jobs: %w", err))
	}

	log.Info().Msg("Vegeta Console started")

	return func() {
		c.cancel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.server.Shutdown(ctx); err != nil {
			log.Error().
				Err(err).
				Msg("Error in shutting down HTTP server")
		}
		wg.Wait()

		log.Info().Msg("Vegeta Console stopped")
	}
}

func createMongoIndices(ctx context.Context, mongodb *mongo.Database) error {

	neededIndexesPerCollection := make(map[string][]mongo.IndexModel)
	neededIndexesPerCollection[model.ScanTasksCollection] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"finishedAt": 1, // index in ascending order
			}, Options: nil,
		},
	}
	neededIndexesPerCollection[model.AssetsContainerCollection] = []mongo.IndexModel{
		// so many indexes on one collection smells...
		{
			Keys: bson.M{
				"lastUpdateTime": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"podName": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"name": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"podOwnerKind": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"podOwnerName": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"isDeleted": 1,
			}, Options: nil,
		},
	}

	for collectionName, indexModel := range neededIndexesPerCollection {
		indexOpts := options.CreateIndexes().SetMaxTime(60 * time.Second)

		col := mongodb.Collection(collectionName)

		logging.GetLogger().Info().Str("collectionName", collectionName).Msg("Ensuring mongo indices")

		// This operation is idempotent
		out, err := col.Indexes().CreateMany(ctx, indexModel, indexOpts)

		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return err
		}

		log.Info().Str("created-indices", fmt.Sprintf("%+v", out)).Str("collectionName", collectionName).Msg("Created mongo indices")
	}

	return nil
}

func initializeOnlineVulnsWatch(ctx context.Context, clusterSvc *cluster.ClusterService, onlineVulnsSvc *onlinevulns.OnlineVulnsService) error {
	// TODO: to do this properly, this should be a method of OnlineVulns
	// however, ClusterService already has dependency on OnlineVulns, so this leads to
	// 1. spaghetti
	// 2. import (dependency) loop
	// Ideally, ClusterService doesn't have dependency on OnlineVulns, and instead
	// has dependency on some Hook interface.
	// However, I will leave this implementation and design when we know more about alerting hooks etc,
	// since it will greatly impact the design of the hook thingy.

	clusters, _, err := clusterSvc.ListClusters(ctx, 0, math.MaxInt64)
	if err != nil {
		return err
	}
	if len(clusters) == 0 {
		return nil
	}
	if len(clusters) != 1 {
		return errors.New("Expected at most 1 cluster at startup")
	}

	// TODO when support multiple clusters, just loop?
	firstCluster := clusters[0]

	kubeClient, err := k8s.KubeClientFromB64KubeConfig(firstCluster.KubeConfig)
	if err != nil {
		return fmt.Errorf("Failed to create kube client from config: %w", err)
	}
	err = k8s.CheckKubeClientConnection(kubeClient)
	if err != nil {
		return fmt.Errorf("Kube client connection check failed: %w", err)
	}

	// to get things started, call OnKubeConfigUpdate
	err = onlineVulnsSvc.OnKubeConfigUpdate(ctx, kubeClient)
	if err != nil {
		return fmt.Errorf("Failed OnKubeConfigUpdate: %w", err)
	}

	return nil

}

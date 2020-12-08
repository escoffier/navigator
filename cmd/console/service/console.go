package service

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	cr "github.com/robfig/cron/v3"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/audit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cleanup"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/onlinevulns"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scanner"
	sp "gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
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
	ruleService        *rule.RuleService
	clusterService     *cluster.ClusterService
	onlineVulnsService *onlinevulns.OnlineVulnsService
	auditService       *audit.AuditService
	cleanupService     *cleanup.CleanupService
	harborClient       *harbor.HarborRESTClient
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
	harborOpts *flag.HarborOpts,
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
		Password: redisOpts.Password, // TODO: Add authorization
		DB:       0,                  // TODO: Add DB
	})

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// rule service
	ruleService := rule.NewRuleService(mainCtx, rulesOpts.AvailableRulesFolder, mongodb, redisClient)

	// audit service
	auditService := audit.NewAuditService(mongodb)

	// cleanup service
	cleanupService := cleanup.NewCleanupService(mongodb, mongoOpts.PVC, mongoOpts.Pod, mongoOpts.DataPath)

	// scanner service
	scannerService := scanner.NewScannerService(mainCtx, redisClient, mongodb)

	es, err := elastic.NewClient(
		elastic.SetURL(fmt.Sprintf("http://%s:%s", elasticOpts.Host, elasticOpts.Port)),
		elastic.SetBasicAuth(elasticOpts.Username, elasticOpts.Password),
	)
	if err != nil {
		return nil, err
	}

	// online vulns service
	onlineVulnsSvc := onlinevulns.NewOnlineVulnsService(mongodb)

	// cluster service
	clusterService := cluster.NewClusterService(mainCtx, mongodb, onlineVulnsSvc, cleanupService, redisClient)

	// scap service
	scapper := &sp.Scapper{
		DockerRepoHostPort: scapOpts.HostPort,
		DockerRepoScapTag:  scapOpts.ImageTag,
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
	cronService := cron.NewCronService(c, mongodb, scapper, clusterService, mainCtx)

	// alert service
	alertService := alert.NewAlertService(mainCtx, redisClient, ruleService, es, elasticOpts.Index, mongodb)

	// scap service
	scapService, err := sp.NewScapService(mainCtx, redisClient, mongodb)
	if err != nil {
		return nil, err
	}

	harborClient, err := harbor.NewHarborRESTClient(mainCtx, harborOpts)
	if err != nil {
		return nil, err
	}

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
				auditService,
				cleanupService,
				scannerService,
				scapService,
				harborClient,
			),
		},
		mongoClient:        mongoClient,
		mongodb:            mongodb,
		cronService:        cronService,
		ctx:                mainCtx,
		cancel:             mainCancel,
		clusterService:     clusterService,
		ruleService:        ruleService,
		onlineVulnsService: onlineVulnsSvc,
		auditService:       auditService,
		cleanupService:     cleanupService,
		harborClient:       harborClient,
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

	testCtx, testCancel := context.WithTimeout(ctx, time.Second*10)
	defer testCancel()
	canDowngrade := true
	err = c.harborClient.TestConnectionAndAdminPrivileges(testCtx, canDowngrade)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Harbor connection and admin privilege check failed")
		panic(fmt.Errorf("Harbor connection and admin privilege check failed: %w", err))
	}

	err = createMongoIndices(ctx, c.mongodb)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When creating mongo indices")
		panic(fmt.Errorf("When creating mongo indices: %w", err))
	}

	err = initializeAuditConfig(ctx, c.mongodb, c.auditService)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When initializing audit config")
		panic(fmt.Errorf("When initializing audit config: %w", err))
	}

	err = initializeRulesDefinitions(ctx, c.ruleService, c.mongodb)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When initializing rules definitions")
		panic(fmt.Errorf("When initializing rules definitions: %w", err))
	}

	kubeClient, restConfig, err := getCurrentKubeClient(ctx, c.clusterService)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When validating kube client")
		panic(fmt.Errorf("When validating kube client: %w", err))
	}
	if kubeClient != nil {
		err = initializeOnlineVulnsWatch(ctx, c.onlineVulnsService, kubeClient)
		if err != nil {
			log.Error().
				Err(err).
				Msg("When initializing online vulns watch")
			panic(fmt.Errorf("When initializing online vulns watch: %w", err))
		}
		c.cleanupService.OnKubeConfigUpdate(kubeClient, restConfig)
	}

	err = c.cronService.StartCrons(ctx)
	if err != nil {
		log.Error().Err(err).Msg("When starting cron jobs")
		panic(fmt.Errorf("When starting cron jobs: %w", err))
	}

	log.Info().Msg("TensorNavigator started")

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

		log.Info().Msg("TensorNavigator stopped")
	}
}

func initializeAuditConfig(ctx context.Context, mongodb *mongo.Database, auditService *audit.AuditService) error {
	_, err := auditService.GetAuditConfig(ctx)
	if err != nil {
		switch err.(type) {
		case AuditConfigDoesntExistError:
			// Continue with setting default values
		default:
			return err
		}
	} else {
		return nil
	}

	// Default values on startup
	auditConfig := &model.AuditConfig{
		ColdStorageDays: 90,
	}

	_, err = auditService.AddAuditConfig(ctx, auditConfig)
	if err != nil {
		return err
	}
	return nil
}

func initializeRulesDefinitions(ctx context.Context, rulesService *rule.RuleService, mongodb *mongo.Database) error {
	availableRulesFiles, err := ioutil.ReadDir(rulesService.AvailableRulesFolderPath)
	if err != nil {
		return err
	}

	for _, file := range availableRulesFiles {
		filenameSplit := strings.Split(file.Name(), ".yaml")
		if len(filenameSplit) <= 1 {
			continue
		}
		ruleName := filenameSplit[0]
		logging.GetLogger().Info().Str("rule", ruleName).Msg("Processing rule")

		var ruleDefinition model.RuleDefinition
		filter := bson.M{"name_en": ruleName}

		queryResult := mongodb.Collection(model.RulesDefinitionsCollection.String()).FindOne(ctx, filter)
		if queryResult.Err() != nil {
			if queryResult.Err() == mongo.ErrNoDocuments {
				logging.GetLogger().Info().Str("rule", ruleName).Msg("Rule definition not present in the db")
				ruleYamlFile, err := ioutil.ReadFile(rulesService.AvailableRulesFolderPath + "/" + file.Name())
				if err != nil {
					return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot read rule definition %s: %w", rulesService.AvailableRulesFolderPath+"/"+file.Name(), err))
				}
				err = yaml.Unmarshal(ruleYamlFile, &ruleDefinition)
				if err != nil {
					return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot unmarshal rules definition %s: %w", rulesService.AvailableRulesFolderPath+"/"+file.Name(), err))
				}
				logging.GetLogger().Info().Str("rule", file.Name()).Msg("Rule successfully parsed")

				ruleDefinition.ID = primitive.NewObjectIDFromTimestamp(time.Now())
				_, err = mongodb.Collection(model.RulesDefinitionsCollection.String()).InsertOne(ctx, ruleDefinition)
				if err != nil {
					return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
				}

				var newRule model.Rule

				newRule.NameEn = ruleDefinition.NameEn
				newRule.CreatedAt = time.Now()
				newRule.NameZh = ruleDefinition.NameZh
				newRule.DescriptionEn = ruleDefinition.DescriptionEn
				newRule.DescriptionZh = ruleDefinition.DescriptionZh
				newRule.Cvss3Score = ruleDefinition.Cvss3Score
				newRule.Enabled = false
				newRule.Cvss3Vector = ruleDefinition.Cvss3Vector
				newRule.Cvss2Score = ruleDefinition.Cvss2Score
				newRule.Cvss2Vector = ruleDefinition.Cvss2Vector
				newRule.ID = primitive.NewObjectIDFromTimestamp(time.Now())
				_, err = mongodb.Collection(model.RulesCollection.String()).InsertOne(ctx, newRule)
				if err != nil {
					return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
				}
			} else {
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
			}
		} else {
			logging.GetLogger().Info().Str("rule", ruleName).Msg("Rule definition already exists")
		}
	}
	return nil
}

func createMongoIndices(ctx context.Context, mongodb *mongo.Database) error {
	neededIndexesPerCollection := make(map[string][]mongo.IndexModel)
	neededIndexesPerCollection[model.ScanTasksCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"finishedAt": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"firstScanAt": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"scan_report.overallSeverity": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"scan_report.overallSeverityInt": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"repository": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"tag": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"imageDigest": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"stale": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"status": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"digest": 1,
			}, Options: nil,
		},
	}
	for _, col := range []string{model.ComplianceCheckKubeRecordsCollection.String(),
		model.ComplianceCheckDockerRecordsCollection.String(),
		model.ComplianceCheckHostRecordsCollection.String()} {

		neededIndexesPerCollection[col] = []mongo.IndexModel{
			{
				Keys: bson.M{
					"checkId": 1,
				}, Options: nil,
			},
			{
				Keys: bson.M{
					"nodeName": 1,
				}, Options: nil,
			},
			{
				Keys: bson.M{
					"status": 1,
				}, Options: nil,
			},
		}
	}
	neededIndexesPerCollection[model.CheckHistoryEntryCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"createdAt": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"finishedAt": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"checkID": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"numSuccessful": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"numFailed": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"numError": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"numWaiting": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"numInconclusive": 1,
			}, Options: nil,
		},
	}
	neededIndexesPerCollection[model.AssetsContainersCollection.String()] = []mongo.IndexModel{
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
				"namespace": 1,
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
		{
			Keys: bson.M{
				"digest": 1,
			}, Options: nil,
		},
	}
	neededIndexesPerCollection[model.AlertsCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"timestamp": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"alertKind": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"imageScanAlert.elasticId": 1,
			}, Options: nil,
		},
	}
	neededIndexesPerCollection[model.RulesCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"name": 1,
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

func getCurrentKubeClient(ctx context.Context, clusterSvc *cluster.ClusterService) (*kubernetes.Clientset, *rest.Config, error) {
	clusters, _, err := clusterSvc.ListClusters(ctx, 0, math.MaxInt64)
	if err != nil {
		return nil, nil, err
	}
	if len(clusters) == 0 {
		return nil, nil, nil
	}
	if len(clusters) != 1 {
		return nil, nil, errors.New("Expected at most 1 cluster at startup")
	}

	// TODO when support multiple clusters, just loop?
	firstCluster := clusters[0]

	kubeClient, err := k8s.KubeClientFromB64KubeConfig(firstCluster.KubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create kube client from config: %w", err)
	}
	restConfig, err := k8s.GetRestConfigFromKubeConfig(firstCluster.KubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get k8s rest config: %w", err)
	}
	err = k8s.CheckKubeClientConnection(kubeClient)
	if err != nil {
		return nil, nil, fmt.Errorf("Kube client connection check failed: %w", err)
	}
	return kubeClient, restConfig, nil
}

func initializeOnlineVulnsWatch(ctx context.Context, onlineVulnsSvc *onlinevulns.OnlineVulnsService, kubeClient *kubernetes.Clientset) error {
	// TODO: to do this properly, this should be a method of OnlineVulns
	// however, ClusterService already has dependency on OnlineVulns, so this leads to
	// 1. spaghetti
	// 2. import (dependency) loop
	// Ideally, ClusterService doesn't have dependency on OnlineVulns, and instead
	// has dependency on some Hook interface.
	// However, I will leave this implementation and design when we know more about alerting hooks etc,
	// since it will greatly impact the design of the hook thingy.

	// to get things started, call OnKubeConfigUpdate
	err := onlineVulnsSvc.OnKubeConfigUpdate(ctx, kubeClient)
	if err != nil {
		return fmt.Errorf("Failed OnKubeConfigUpdate: %w", err)
	}

	return nil
}

package service

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/networktopo"
	"math"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/olivere/elastic/v7"
	cr "github.com/robfig/cron/v3"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/image"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/microservice"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/riskexplorer"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scanner"
	sp "gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/cmd/data/notifyhandler"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	log *logging.Logger
)

const (
	defaultK8sClusterName = "default"
)

const (
	eventGrpcUrlEnv     = "EVENT_GRPC_URL"
	defaultEventGrpcUrl = "tensorsec-eventcenter:9090"

	eventGrpcCertPathEnv     = "EVENT_GRPC_CERT_PATH"
	defaultEventGrpcCertPath = "/auth/server/tls.crt"

	eventGrpcCertServerNameEnv     = "EVENT_GRPC_CERT_SERVER_NAME"
	defaultEventGrpcCertServerName = "tensorsec-eventcenter"
)

func init() {
	log = logging.GetLogger()
}

// Console represents the Vegeta Console server.
type Console struct {
	lifecycle.Service
	server             *http.Server
	monCliWrapper      *mongotools.ClientWrapper
	mongoDB            *mongotools.DatabaseWrapper
	postgresDB         *rdbtools.GormWrapper
	es                 *elastic.Client
	cronService        *cron.CronService
	clusterService     *cluster.ClusterService
	onlineVulnsService *assetsSvc.AssetsInResourcesService
	svcAssetsService   *assetsSvc.ServiceAssetsService
	dataService        *data.Service
	harborClient       *harbor.HarborRESTClient
	ctx                context.Context
	cancel             context.CancelFunc
}

// NewConsole is to create a new Console struct.
func NewConsole(
	httpOpts *flag.HTTPOpts,
	mongoOpts *flag.MongoOpts,
	postgresOpts *flag.PostgresOpts,
	scannerOpts *flag.VegetaScannerOpts,
	scapOpts *flag.ScapOpts,
	redisOpts *flag.RedisOpts,
	elasticOpts *flag.ElasticOpts,
	harborOpts *flag.HarborOpts,
	emailOpts *flag.EmailOpts,
) (*Console, error) {
	// mongo client
	// TODO: authSource database should be a separate argument.
	mongoString := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=%s", mongoOpts.Username, mongoOpts.Password, mongoOpts.Endpoint, mongoOpts.Database)
	mongoClientOptions := options.Client().ApplyURI(mongoString)
	mongoClientOptions.SetPoolMonitor(&event.PoolMonitor{
		Event: mongotools.PoolMonitorFunc,
	})
	mongoClientOptions.SetWriteConcern(writeconcern.New(writeconcern.WMajority()))
	mongoClientOptions.SetReadConcern(readconcern.Majority())
	mongoClientOptions.SetMaxPoolSize(50)
	mongoClientOptions.SetMaxConnIdleTime(10 * time.Minute)
	mongoClientOptions.SetConnectTimeout(1 * time.Second)
	mongoClientOptions.SetMinPoolSize(5)
	mongoCliWrapper, wrErr := mongotools.NewMongoClient(mongoClientOptions, 1*time.Second)
	if wrErr != nil {
		return nil, wrErr
	}

	mongoDBWrapper := mongoCliWrapper.Database(mongoOpts.Database)
	eventGrpcUrl := os.Getenv(eventGrpcUrlEnv)
	if eventGrpcUrl == "" {
		eventGrpcUrl = defaultEventGrpcUrl
	}

	eventGrpcCertPath := os.Getenv(eventGrpcCertPathEnv)
	if eventGrpcCertPath == "" {
		eventGrpcCertPath = defaultEventGrpcCertPath
	}

	eventGrpcCertServerName := os.Getenv(eventGrpcCertServerNameEnv)
	if eventGrpcCertServerName == "" {
		eventGrpcCertServerName = defaultEventGrpcCertServerName
	}

	cred, err := credentials.NewClientTLSFromFile(eventGrpcCertPath, eventGrpcCertServerName)
	if err != nil {
		panic(err)
	}

	conn, err := grpc.Dial(eventGrpcUrl, grpc.WithTransportCredentials(cred))
	if err != nil {
		return nil, err
	}
	ecCli := pb.NewEventsCenterBizServiceClient(conn)

	// Redis DB client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisOpts.Endpoint,
		Password: redisOpts.Password, // TODO: Add authorization
		DB:       0,                  // TODO: Add DB
	})

	postgresDB, err := rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
		db, err := gorm.Open(postgres.Open(postgresOpts.PostgresConnectionString), &gorm.Config{})
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
			return nil, err
		}
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.SetMaxOpenConns(30)
			sqlDB.SetMaxIdleConns(5)
			sqlDB.SetConnMaxIdleTime(10 * time.Minute)
			sqlDB.SetConnMaxLifetime(time.Hour)
		}
		return db, nil
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("Init postgre error")
		return nil, err
	}

	postgresDB.Get().AutoMigrate(&model.User{})
	postgresDB.Get().AutoMigrate(&model.Email{})
	postgresDB.Get().AutoMigrate(&model.ImageList{})
	postgresDB.Get().AutoMigrate(&model.QuestionInfo{})

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// harbor client
	harborClient, err := harbor.NewHarborRESTClient(mainCtx, harborOpts)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Sprintf("ERROR: harbor client init error :%s ", err))
	}
	// image service
	imageService := image.NewImageService(postgresDB, harborClient)

	// scanner service
	scannerService := scanner.NewScannerService(mainCtx, redisClient, postgresDB, mongoDBWrapper, harborClient)

	es, err := elastic.NewClient(
		elastic.SetURL(fmt.Sprintf("http://%s:%s", elasticOpts.Host, elasticOpts.Port)),
		elastic.SetBasicAuth(elasticOpts.Username, elasticOpts.Password),
	)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Sprintf("ERROR: elastic client init error :%s ", err))
	}

	// data service
	emailPort, err := strconv.Atoi(emailOpts.Port)
	if err != nil {
		logging.GetLogger().Error().Msgf("invalid email port:%s", emailOpts.Port)
	}

	dataService := data.NewService(&data.Conf{
		Mongodb:    mongoDBWrapper,
		PostgresDB: postgresDB,
		EmailConf: &notifyhandler.EmailConf{
			Username: emailOpts.Username,
			Password: emailOpts.Password,
			Host:     emailOpts.Host,
			Port:     emailPort,
		},
		MongoPod: &data.PodInfo{
			PVC:      mongoOpts.PVC,
			Pod:      mongoOpts.Pod,
			DataPath: mongoOpts.DataPath,
		},

		ESPod: &data.PodInfo{
			PVC:      elasticOpts.PVC,
			Pod:      elasticOpts.Pod,
			DataPath: elasticOpts.DataPath,
		},

		PostgrePod: &data.PodInfo{
			PVC:      postgresOpts.PVC,
			Pod:      postgresOpts.Pod,
			DataPath: postgresOpts.DataPath,
		},

		AuditPod: &data.PodInfo{
			PVC:      os.Getenv("AUDIT_PVC"),
			Pod:      os.Getenv("MY_POD_NAME"),
			DataPath: os.Getenv("AUDIT_PATH"),
		},
	})

	// online vulns service
	onlineVulnsSvc := assetsSvc.NewAssetsInResources(mongoDBWrapper, postgresDB)

	// service assets service
	svcAssetsSvc, svcErr := assetsSvc.InitAndGetServiceAssetsService(mongoDBWrapper)
	if svcErr != nil {
		logging.GetLogger().Err(svcErr).Msgf("ERROR: ServiceAssetsService init error")
	}

	// cluster service
	clusterService := cluster.NewClusterService(mainCtx, postgresDB, mongoDBWrapper, onlineVulnsSvc, redisClient)

	// scap service
	scapService, err := sp.NewScapService(mainCtx, redisClient, mongoDBWrapper)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Sprintf("ERROR: scapService  init error :%s ", err))
	}

	// scapper
	scapper := sp.NewScapper(scapOpts, mongoOpts, mongoDBWrapper, scapService)

	// cron service
	c := cr.New()
	c.Start()
	cronService := cron.NewCronService(c, mongoDBWrapper, scapper, clusterService, mainCtx)

	//microService *microservice.MicroService,
	//micro service
	microService := microservice.NewMicroService(mongoDBWrapper, postgresDB)

	riskexplorer.InitAndGetRiskExplorerService(mongoDBWrapper, onlineVulnsSvc)

	// networkTopo service
	networkTopoService := networktopo.NewNetworkTopoService(postgresDB)

	return &Console{
		server: &http.Server{
			Addr: httpOpts.HTTPListen,
			Handler: setupChiRouter(
				mainCtx,
				mongoDBWrapper,
				postgresDB,
				es,
				scapper,
				fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port),
				httpOpts.HTTPLoggerDisabled,
				cronService,
				clusterService,
				redisClient,
				onlineVulnsSvc,
				dataService,
				scannerService,
				scapService,
				harborClient,
				microService,
				emailOpts,
				imageService,
				ecCli,
				networkTopoService,
			),
		},
		monCliWrapper:      mongoCliWrapper,
		mongoDB:            mongoDBWrapper,
		postgresDB:         postgresDB,
		es:                 es,
		cronService:        cronService,
		ctx:                mainCtx,
		cancel:             mainCancel,
		clusterService:     clusterService,
		onlineVulnsService: onlineVulnsSvc,
		svcAssetsService:   svcAssetsSvc,
		dataService:        dataService,
		harborClient:       harborClient,
	}, nil
}

// Run is to run the service.
func (c *Console) Run() func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		defer wg.Done()
		if err := c.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Error().Err(err).Msg("error in http.Server.ListenAndServe")
			}
		}
	}()

	// ctx for initialization steps
	ctx, mcancel := context.WithTimeout(c.ctx, 60*time.Second)
	defer mcancel()
	err := c.monCliWrapper.Connect(ctx)
	if err != nil {
		log.Error().Err(err).Msg("When in connecting to Mongo database")
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
	}

	err = postgreCheck(c.postgresDB)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When check admin data in postgres")
	}

	err = createMongoIndices(ctx, c.mongoDB)
	if err != nil {
		log.Error().
			Err(err).
			Msg("When creating mongo indices")
		panic(fmt.Errorf("When creating mongo indices: %w", err))
	}

	err = addDefaultCluster(ctx, c.mongoDB)
	if err != nil {
		logging.GetLogger().Error().Msgf("add cluster error：%+v", err)
	}

	kubeClient, _, err := getCurrentKubeClientWithServiceAccount()
	if err != nil {
		log.Error().
			Err(err).
			Msg("When validating kube client")
	}
	if kubeClient != nil {
		watcher, werr := assetsSvc.Watcher(c.postgresDB, c.svcAssetsService, c.onlineVulnsService)
		if werr != nil {
			log.Error().Err(err).Msgf("get assetsWatcher error: %v", werr)
		} else {
			err := watcher.StartsToWatch(ctx, map[string]*kubernetes.Clientset{
				defaultK8sClusterName: kubeClient,
			})
			if err != nil {
				log.Error().Err(err).Msg("Watch kube clients error")
			}
		}
	}

	err = c.cronService.StartCrons(ctx)
	if err != nil {
		log.Error().Err(err).Msg("When starting cron jobs")
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

func postgreCheck(db *rdbtools.GormWrapper) error {

	queryUser := model.User{}
	err := db.Get().Where("username = ?", model.SUPER_ADMIN).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		salt := model.RandStringBytesMaskImprSrcUnsafe(8)
		hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(model.SUPER_PWD+salt)))
		user := model.User{UserName: model.SUPER_ADMIN, Checked: true, CreateAt: time.Now().Unix(), Rule: model.ROLE_SUPERADMIN, Salt: salt, Pwd: hashPwd}
		err = db.Get().Create(&user).Error
		if err != nil {
			return err
		}
	}

	db.Get().Migrator().DropTable(&model.ModuleGroup{}, &model.Url{})
	db.Get().AutoMigrate(&model.ModuleGroup{}, &model.Url{})

	mg1 := model.ModuleGroup{
		ModuleName_zh: "用户中心",
		ModuleName_en: "User Center",
	}

	mg2 := model.ModuleGroup{
		ModuleName_zh: "平台",
		ModuleName_en: "Platform",
	}

	mg3 := model.ModuleGroup{
		ModuleName_zh: "容器安全",
		ModuleName_en: "Container security",
	}

	db.Get().Table(model.ModuleGroup{}.TableName()).Create(&mg1)
	db.Get().Table(model.ModuleGroup{}.TableName()).Create(&mg2)
	db.Get().Table(model.ModuleGroup{}.TableName()).Create(&mg3)

	url1 := model.Url{UrlName: "/api/v2/usercenter", UrlId: mg1.Id}
	url2 := model.Url{UrlName: "/api/v2/platform", UrlId: mg2.Id}
	url3 := model.Url{UrlName: "/api/v2/containerSec", UrlId: mg3.Id}

	db.Get().Table(model.Url{}.TableName()).Create(&url1)
	db.Get().Table(model.Url{}.TableName()).Create(&url2)
	db.Get().Table(model.Url{}.TableName()).Create(&url3)

	return nil
}

func createMongoIndices(ctx context.Context, mongodb *mongotools.DatabaseWrapper) error {
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
	neededIndexesPerCollection[model.VulnerabilitiesInImagesCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"vulnInfo.id": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"historicised_timestamp": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"scanType": 1,
			}, Options: nil,
		},
	}
	neededIndexesPerCollection[model.PodServiceRelationCollection.String()] = []mongo.IndexModel{
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
				"cluster": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"podUid": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"ip": 1,
			}, Options: nil,
		},
	}
	neededIndexesPerCollection[model.PodOwnerRefRelationCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"ownerRefName": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"namespace": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"cluster": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"podUid": 1,
			}, Options: nil,
		},
	}

	neededIndexesPerCollection[model.ServiceRelationCollection.String()] = []mongo.IndexModel{
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
				"focusName": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"resName": 1,
			}, Options: nil,
		},
	}

	neededIndexesPerCollection[model.ServiceAliasCollection.String()] = []mongo.IndexModel{
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
				"aliasName": 1,
			}, Options: nil,
		},
	}

	neededIndexesPerCollection[model.HarborProjectConfigCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"CheckID": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"CreatedAt": 1,
			}, Options: nil,
		},
	}

	neededIndexesPerCollection[model.TensorServiceCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"namespace": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"cluster": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"serviceName": 1,
			}, Options: nil,
		},

		{
			Keys: bson.M{
				"updatedAt": 1,
			}, Options: nil,
		},
	}

	neededIndexesPerCollection[model.ImageListCollection.String()] = []mongo.IndexModel{
		{
			Keys: bson.M{
				"full_repo_name": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"tags": 1,
			}, Options: nil,
		},
		{
			Keys: bson.M{
				"digest": 1,
			}, Options: nil,
		},
	}

	for collectionName, indexModel := range neededIndexesPerCollection {
		indexOpts := options.CreateIndexes().SetMaxTime(60 * time.Second)

		col := mongodb.Get().Collection(collectionName)

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

	logging.GetLogger().Info().
		Msg("Cluster already exists")

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

func getCurrentKubeClientWithServiceAccount() (*kubernetes.Clientset, *rest.Config, error) {
	return k8s.KubeClientFromServiceAccoount()
}

func addDefaultCluster(ctx context.Context, mongodb *mongotools.DatabaseWrapper) error {
	newCluster := &model.Cluster{
		ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
		ClusterName: "default",
		KubeConfig:  "",
		CreatedAt:   time.Now(),
	}

	collection := mongodb.Get().Collection(model.ClusterCollection.String())

	err := mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}
		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		filter := bson.M{"name": newCluster.ClusterName, "deleted_at": bson.M{"$exists": false}}
		queryResult := collection.FindOne(sessionContext, filter)

		if queryResult.Err() == mongo.ErrNoDocuments {
			logging.GetLogger().Error().Msgf("default cluster exist,add cluster ")
			_, sessionError = collection.InsertOne(sessionContext, newCluster)
			if sessionError != nil {
				logging.GetLogger().Error().Msgf("add cluster error:%+v", sessionContext)
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
			}
		} else {
			return queryResult.Err()
		}

		return nil
	})
	if err != nil {
		logging.GetLogger().Error().Msgf("add cluster error:%+v", err)
		return err
	}
	return nil
}

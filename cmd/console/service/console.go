package service

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/olivere/elastic/v7"
	cr "github.com/robfig/cron/v3"
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
	certutil "k8s.io/client-go/util/cert"

	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/config"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/k8saudit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/kubemonitor"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/networktopo"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/openapiauth"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/riskexplorer"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	sp "gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	"gitlab.com/piccolo_su/vegeta/cmd/data/notifyhandler"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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

	maxClusterNum = 1000
)

func init() {
	log = logging.GetLogger()
}

// Console represents the Vegeta Console server.
type Console struct {
	lifecycle.Service
	server        *http.Server
	webHookServer *http.Server
	monCliWrapper *mongotools.ClientWrapper
	mongoDB       *mongotools.DatabaseWrapper
	postgresDB    *rdbtools.GormWrapper
	es            *elastic.Client
	harborClient  *harbor.HarborRESTClient
	ctx           context.Context
	cancel        context.CancelFunc
	scannerURL    string
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
	secProfilesOpts *flag.SecProfilesOpts,
	microsegOpts *flag.MicrosegOpts,
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

	const (
		maxGrpcReceiveMsgSize = 1024 * 1024 * 1024
	)

	conn, err := grpc.Dial(eventGrpcUrl, grpc.WithTransportCredentials(cred),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxGrpcReceiveMsgSize)))
	if err != nil {
		return nil, err
	}
	ecBuzCli := pb.NewEventsCenterBizServiceClient(conn)
	ecColCli := pb.NewEventsCenterCollectionServiceClient(conn)

	// Redis DB client
	sa := strings.Split(redisOpts.Endpoint, ",")
	redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      redisOpts.Password,
		DB:            0,
	})
	if err != nil {
		return nil, err
	}

	PgDsn := postgresOpts.PostgresConnectionString
	postgresDB, err := rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {

		db, err := gorm.Open(postgres.Open(PgDsn), &gorm.Config{})
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
			return nil, err
		}
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.SetMaxOpenConns(30)
			sqlDB.SetMaxIdleConns(5)
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
	postgresDB.Get().AutoMigrate(&model.TensorMicrosegResource{})
	postgresDB.Get().AutoMigrate(&model.TensorResource{})
	postgresDB.Get().AutoMigrate(&model.TensorContainer{})
	postgresDB.Get().AutoMigrate(&model.TensorNamespace{})
	postgresDB.Get().AutoMigrate(&model.TensorConfig{})
	postgresDB.Get().AutoMigrate(&model.ScanResult{})
	postgresDB.Get().AutoMigrate(&model.ScanHistory{})
	postgresDB.Get().AutoMigrate(&model.ScanNodeRecord{})
	postgresDB.Get().AutoMigrate(&model.PolicyDetailInfo{})
	postgresDB.Get().AutoMigrate(&model.ExportTask{})
	postgresDB.Get().AutoMigrate(&model.PodResourceRelation{})
	postgresDB.Get().AutoMigrate(&model.TensorCluster{})
	postgresDB.Get().AutoMigrate(&model.OpenAPIAuthToken{})
	postgresDB.Get().AutoMigrate(&model.GCTask{})
	postgresDB.Get().AutoMigrate(&model.TensorNetworkFlow{})

	scannerURL := fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port)

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// harbor client
	harborClient, err := harbor.NewHarborRESTClient(mainCtx, harborOpts)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Sprintf("ERROR: harbor client init error :%s ", err))
	}

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

	err = data.Init(&data.Conf{
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
	if err != nil {
		logging.GetLogger().Err(err).Msgf("ERROR: DataService init error")
	}

	rlErr := assetsSvc.InitResourcesService(postgresDB, scannerURL)
	if rlErr != nil {
		logging.GetLogger().Err(rlErr).Msgf("ERROR: InitResourcesService init error")
	}

	kbmErr := kubemonitor.Init(ecColCli)
	if err != nil {
		logging.GetLogger().Err(kbmErr).Msgf("ERROR: kubeMonitor init error")
	}
	svcErr := assetsSvc.Init(redisClient, postgresDB)
	if svcErr != nil {
		logging.GetLogger().Err(svcErr).Msgf("ERROR: ServiceAssetsService init error")
	}

	ucErr := usercenter.Init(postgresDB)
	if ucErr != nil {
		logging.GetLogger().Err(svcErr).Msgf("ERROR: usercenter limiter init error")
	}
	// cluster service
	cluster.Init(mainCtx, postgresDB, mongoDBWrapper, redisClient, fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port))

	// scap service
	err = sp.Init(mainCtx, scapOpts, mongoOpts, redisClient, mongoDBWrapper, PgDsn, postgresDB)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Sprintf("ERROR: scapService  init error :%s ", err))
	}

	// cron service
	c := cr.New()
	c.Start()
	cron.Init(c, mongoDBWrapper, mainCtx)

	reErr := riskexplorer.Init(scannerURL, redisClient)
	if reErr != nil {
		logging.GetLogger().Err(reErr).Msgf("ERROR: riskexplorerService init error")
	}

	// networkTopo service
	ntErr := networktopo.Init(postgresDB)
	if ntErr != nil {
		logging.GetLogger().Err(ntErr).Msgf("ERROR: networkFlowService init error")
	}

	err = config.Init(postgresDB)
	if err != nil {
		logging.GetLogger().Err(ntErr).Msgf("ERROR: config service init error")
	}

	err = k8saudit.Init(postgresDB, es)
	if err != nil {
		logging.GetLogger().Err(ntErr).Msgf("ERROR: k8s-audit service init error")
		return nil, err
	}

	err = openapiauth.Init(postgresDB, redisClient)
	if err != nil {
		logging.GetLogger().Err(ntErr).Msgf("ERROR: openapi auth service init error")
		return nil, err
	}

	return &Console{
		server: &http.Server{
			Addr: httpOpts.HTTPListen,
			Handler: setupChiRouter(
				mainCtx,
				mongoDBWrapper,
				postgresDB,
				es,
				scannerURL,
				fmt.Sprintf("http://%s:%d", secProfilesOpts.Host, secProfilesOpts.Port),
				fmt.Sprintf("http://%s:%d", microsegOpts.Host, microsegOpts.Port),
				httpOpts.HTTPLoggerDisabled,
				redisClient,
				harborClient,
				emailOpts,
				ecBuzCli,
			),
		},
		webHookServer: &http.Server{Addr: httpOpts.HTTPWebHookListen, Handler: setupWebHookRouter()},
		monCliWrapper: mongoCliWrapper,
		mongoDB:       mongoDBWrapper,
		postgresDB:    postgresDB,
		es:            es,
		ctx:           mainCtx,
		cancel:        mainCancel,
		harborClient:  harborClient,
		scannerURL:    scannerURL,
	}, nil
}

// Run is to run the service.
func (c *Console) Run() func() {
	var wg sync.WaitGroup
	wg.Add(2)
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
	// webhook
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		defer wg.Done()
		if err := c.webHookServer.ListenAndServe(); err != nil {
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
	}

	//writing cluster info into mongodb would be deleted later
	err = addDefaultCluster(ctx, c.mongoDB)
	if err != nil {
		logging.GetLogger().Error().Msgf("add cluster error：%+v", err)
	}

	clients := getAllKubeClient(ctx)
	k8s.WatchKubeResource(ctx, clients, c.postgresDB, c.scannerURL)

	cronService, _ := cron.Get(ctx)
	err = cronService.StartCrons(ctx)
	if err != nil {
		log.Error().Err(err).Msg("When starting cron jobs")
	}

	scapper, _ := scapper.GetScapper(ctx)
	err = scapper.InitCheckUnFinishedJobs(ctx)
	if err != nil {
		log.Error().Err(err).Msg("When scapper InitCheckUnFinishedJobs")
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

const (
	postgreCheckTimeout = time.Minute
)

func postgreCheck(db *rdbtools.GormWrapper) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgreCheckTimeout)
	defer cancel()
	queryUser := model.User{}
	err := db.Get().WithContext(ctx).Where("username = ?", model.UserSuperAdmin).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		salt := dal.RandStringBytesMaskImprSrcUnsafe(8)
		hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(model.PasswordSuperAdmin+salt)))
		user := model.User{UserName: model.UserSuperAdmin, Checked: true, CreateAt: time.Now().Unix(), Rule: model.RoleSuperAdmin, Salt: salt, Pwd: hashPwd}
		authToken := util.GenerateUUIDHex()
		err = db.Get().Transaction(func(tx *gorm.DB) error {
			if _err := tx.WithContext(ctx).Create(&user).Error; _err != nil {
				return _err
			}

			return dal.SaveAuthToken(ctx, tx, user.UserName, authToken)
		})
		if err != nil {
			return err
		}
	}

	db.Get().WithContext(ctx).Migrator().DropTable(&model.ModuleGroup{}, &model.Url{})
	db.Get().WithContext(ctx).AutoMigrate(&model.ModuleGroup{}, &model.Url{})

	mg1 := model.ModuleGroup{
		ModuleNameZh: "用户中心",
		ModuleNameEn: "User Center",
	}

	mg2 := model.ModuleGroup{
		ModuleNameZh: "平台",
		ModuleNameEn: "Platform",
	}

	mg3 := model.ModuleGroup{
		ModuleNameZh: "容器安全",
		ModuleNameEn: "Container Security",
	}

	mg4 := model.ModuleGroup{
		ModuleNameZh: "微隔离",
		ModuleNameEn: "Micro Segmentation",
	}

	db.Get().WithContext(ctx).Table(model.ModuleGroup{}.TableName()).Create(&mg1)
	db.Get().WithContext(ctx).Table(model.ModuleGroup{}.TableName()).Create(&mg2)
	db.Get().WithContext(ctx).Table(model.ModuleGroup{}.TableName()).Create(&mg3)
	db.Get().WithContext(ctx).Table(model.ModuleGroup{}.TableName()).Create(&mg4)

	url1 := model.Url{UrlName: "/api/v2/usercenter", UrlId: mg1.Id}
	url2 := model.Url{UrlName: "/api/v2/platform", UrlId: mg2.Id}
	url3 := model.Url{UrlName: "/api/v2/containerSec", UrlId: mg3.Id}
	url4 := model.Url{UrlName: "/api/v2/microseg", UrlId: mg4.Id}

	db.Get().WithContext(ctx).Table(model.Url{}.TableName()).Create(&url1)
	db.Get().WithContext(ctx).Table(model.Url{}.TableName()).Create(&url2)
	db.Get().WithContext(ctx).Table(model.Url{}.TableName()).Create(&url3)
	db.Get().WithContext(ctx).Table(model.Url{}.TableName()).Create(&url4)

	return nil
}

func createMongoIndices(ctx context.Context, mongodb *mongotools.DatabaseWrapper) error {
	neededIndexesPerCollection := make(map[string][]mongo.IndexModel)

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
	err = k8s.CheckKubeClientConnection(ctx, kubeClient)
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
func getAllKubeClient(ctx context.Context) map[string]*kubernetes.Clientset {
	clientMap := make(map[string]*kubernetes.Clientset)

	resSvc, _ := assetsSvc.GetResourcesService(ctx)
	clusters, _, err := resSvc.GetClusters(ctx, 0, maxClusterNum)
	if err != nil {
		return nil
	}

	for _, c := range clusters {
		tlsClientConfig := rest.TLSClientConfig{}
		if _, err := certutil.NewPoolFromBytes([]byte(c.CertificateAuthData)); err != nil {
			log.Error().Err(err).Msg("load root CA config err")
			continue
		} else {
			tlsClientConfig.CAData = []byte(c.CertificateAuthData)
		}
		clientSet, err := kubernetes.NewForConfig(&rest.Config{
			Host:            c.APIServerAddr,
			TLSClientConfig: tlsClientConfig,
			BearerToken:     c.SecretToken,
		})
		if err != nil {
			continue
		}
		clientMap[c.Key] = clientSet
	}
	return clientMap
}

func addDefaultClusterToPG(ctx context.Context) error {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	token := clusterConfig.BearerToken

	ca, err := ioutil.ReadFile(clusterConfig.TLSClientConfig.CAFile)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("read cluster ca file error: %s", clusterConfig.TLSClientConfig.CAFile)
		return err
	}

	key := fmt.Sprintf("%d", util.GenerateUUID(defaultK8sClusterName, clusterConfig.Host))
	newCluster := &model.TensorCluster{
		Key:                 key,
		Name:                defaultK8sClusterName,
		ClusterType:         model.HostCluster,
		APIServerAddr:       clusterConfig.Host,
		SecretToken:         token,
		CertificateAuthData: string(ca),
	}

	resSvc, _ := assetsSvc.GetResourcesService(ctx)
	err = resSvc.AddCluster(ctx, newCluster)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("add default cluster error: %s", key)
		return err
	}
	return nil
}

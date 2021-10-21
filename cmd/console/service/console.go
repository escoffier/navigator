package service

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
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
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/config"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/k8saudit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/networktopo"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/openapiauth"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/processingcenter"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/riskexplorer"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	sp "gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	"gitlab.com/piccolo_su/vegeta/cmd/data/notifyhandler"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/tensorsecurity-rd/go-pkg/pb"
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
	server          *http.Server
	webHookServer   *http.Server
	monCliWrapper   *mongotools.ClientWrapper
	mongoDB         *mongotools.DatabaseWrapper
	postgresDB      *rdbtools.GormWrapper
	es              *elastic.Client
	harborClient    *harbor.HarborRESTClient
	ctx             context.Context
	cancel          context.CancelFunc
	scannerURL      string
	resourceWatcher *assets.Watcher
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
	clusterManagerOpts *flag.ClusterManagerOpts,
	webhookOpts *flag.WebHookOpts,
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

	scannerURL := fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port)
	microsegURL := os.Getenv("TENSORSEC_MICROSEG_HOST")
	clusterManagerURL := fmt.Sprintf("http://%s:%d", clusterManagerOpts.Host, clusterManagerOpts.Port)

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

	ucErr := usercenter.Init(postgresDB)
	if ucErr != nil {
		logging.GetLogger().Err(ucErr).Msgf("ERROR: usercenter limiter init error")
	}

	// scap service
	err = sp.Init(mainCtx, scapOpts, redisClient, PgDsn, postgresDB)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Sprintf("ERROR: scapService  init error :%s ", err))
	}

	// cron service
	c := cr.New()
	c.Start()
	cron.Init(c, postgresDB, mainCtx)

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

	err = captcha.Init(redisClient, captcha.DefaultConf)
	if err != nil {
		logging.GetLogger().Err(ntErr).Msgf("ERROR: captcha service init error")
		return nil, err
	}

	err = session.Init(redisClient, session.DefaultConf)
	if err != nil {
		logging.GetLogger().Err(ntErr).Msgf("ERROR: session service init error")
		return nil, err
	}

	// init cluster manager
	err = k8s.InitClusterManager(postgresDB, nil, clusterManagerURL)
	if err != nil {
		logging.GetLogger().Err(ntErr).Msg("cluster manager init error")
		return nil, err
	}

	err = processingcenter.Init(&processingcenter.ServiceComponent{
		DB:              postgresDB,
		EsCli:           es,
		RedisCli:        redisClient,
		MicroSegBaseURL: microsegURL,
	})

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
				microsegURL,
				fmt.Sprintf("https://%s:%d", webhookOpts.Host, webhookOpts.Port),
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
		log.Error().Err(err).Msg("Harbor connection and admin privilege check failed")
	}

	err = postgreCheck(c.postgresDB)
	if err != nil {
		log.Error().Err(err).Msg("When check admin data in postgres")
	}

	err = createMongoIndices(ctx, c.mongoDB)
	if err != nil {
		log.Error().Err(err).Msg("When creating mongo indices")
	}

	clusterManager, ok := k8s.GetClusterManager()
	if ok {
		err = clusterManager.Start(ctx)
		if err != nil {
			log.Error().Err(err).Msg("When starting cluster manager")
		}
	} else {
		log.Error().Err(errors.New("cluster manager not exist")).Msg("get a nil cluster manager")
	}

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
			log.Error().Err(err).Msg("Error in shutting down HTTP server")
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

	//db.Get().WithContext(ctx).Migrator().DropTable(&model.ModuleGroup{}, &model.Url{})
	//db.Get().WithContext(ctx).AutoMigrate(&model.ModuleGroup{}, &model.Url{})

	mg1 := model.ModuleGroup{
		Id:           1,
		ModuleNameZh: "用户中心",
		ModuleNameEn: "User Center",
	}

	mg2 := model.ModuleGroup{
		Id:           2,
		ModuleNameZh: "平台",
		ModuleNameEn: "Platform",
	}

	mg3 := model.ModuleGroup{
		Id:           3,
		ModuleNameZh: "容器安全",
		ModuleNameEn: "Container Security",
	}

	mg4 := model.ModuleGroup{
		Id:           4,
		ModuleNameZh: "微隔离",
		ModuleNameEn: "Micro Segmentation",
	}

	var modules = []*model.ModuleGroup{&mg1, &mg2, &mg3, &mg4}
	for _, module := range modules {
		if err = db.Get().WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).Create(module).Error; err != nil {
			logging.GetLogger().Err(err).Msgf("init module:%s fail", module.ModuleNameEn)
			return err
		}
	}

	url1 := model.Url{Id: 1, UrlName: "/api/v2/usercenter", UrlId: mg1.Id}
	url2 := model.Url{Id: 2, UrlName: "/api/v2/platform", UrlId: mg2.Id}
	url3 := model.Url{Id: 3, UrlName: "/api/v2/containerSec", UrlId: mg3.Id}
	url4 := model.Url{Id: 4, UrlName: "/api/v2/microseg", UrlId: mg4.Id}

	urls := []*model.Url{&url1, &url2, &url3, &url4}
	for _, url := range urls {
		if err = db.Get().WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).Create(url).Error; err != nil {
			logging.GetLogger().Err(err).Msgf("init url:%s fail", url.UrlName)
			return err
		}
	}

	return nil
}

func createMongoIndices(ctx context.Context, mongodb *mongotools.DatabaseWrapper) error {
	neededIndexesPerCollection := make(map[string][]mongo.IndexModel)

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

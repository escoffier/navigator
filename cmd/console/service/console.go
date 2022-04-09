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
	cr "github.com/robfig/cron/v3"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/apiscan"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/attck"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/defense"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/hunter"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/immune"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/k8saudit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/networktopo"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/openapiauth"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/palace"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/platformreport"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/processingcenter"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/riskexplorer"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	sp "gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	"gitlab.com/piccolo_su/vegeta/cmd/data/notifyhandler"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Console represents the Vegeta Console server.
type Console struct {
	lifecycle.Service
	server        *http.Server
	webHookServer *http.Server
	rdb           *databases.RDBInstance
	es            *elastic.ESClient
	harborClient  *harbor.HarborRESTClient
	cancel        context.CancelFunc
	scannerURL    string
}

// NewConsole is to create a new Console struct.
func NewConsole(
	httpOpts *flag.HTTPOpts,
	rdbOpts *flag.RDBOpts,
	scannerOpts *flag.VegetaScannerOpts,
	scapOpts *flag.ScapOpts,
	elasticOpts *flag.ElasticOpts,
	secProfilesOpts *flag.SecProfilesOpts,
) (*Console, error) {
	eventGrpcUrl := os.Getenv(echelper.EventGrpcURLEnv)
	if eventGrpcUrl == "" {
		eventGrpcUrl = echelper.DefaultEventGrpcURL
	}

	eventGrpcCertPath := os.Getenv(echelper.GrpcCertPathEnv)
	if eventGrpcCertPath == "" {
		eventGrpcCertPath = echelper.DefaultGrpcCertPath
	}

	eventGrpcCertServerName := os.Getenv(echelper.GrpcCertServerNameEnv)
	if eventGrpcCertServerName == "" {
		eventGrpcCertServerName = echelper.DefaultGrpcCertServerName
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

	ecenterCli, err := echelper.NewEventCenterClient()
	if err != nil {
		return nil, err
	}
	// Redis DB client
	redisEndpoint := env.GetRedisEndpoint()
	sa := strings.Split(redisEndpoint, ",")
	redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      env.GetRedisPassword(),
		DB:            0,
	})
	if err != nil {
		return nil, err
	}

	rdb, err := databases.NewRDBWithMySQLByEnv(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("Init DB error")
		return nil, err
	}

	scannerURL := fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port)
	microsegURL := os.Getenv("MICROSEG_URL")
	clusterManagerURL := env.GetClusterManagerUrl()

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// harbor client for tensor harbor adapter
	// temperately comment,need refactor
	//harborClient, err := harbor.NewHarborRESTClient(mainCtx, harborOpts)
	//if err != nil {
	//	logging.Get().Error().Msg(fmt.Sprintf("ERROR: harbor client init error :%s ", err))
	//}

	es := elastic.NewESClientWithEnv(context.Background())

	if err = immune.Init(rdb); err != nil {
		logging.Get().Err(err).Msg("Init immune error")
	}
	if err = palace.Init(rdb, es); err != nil {
		logging.Get().Err(err).Msg("Init palace error")
	}

	// data service
	emailPort, err := strconv.Atoi(env.GetEmailPort())
	if err != nil {
		logging.Get().Error().Msgf("invalid email port:%s", env.GetEmailPort())
	}

	err = data.Init(&data.Conf{
		RDB: rdb,
		EmailConf: &notifyhandler.EmailConf{
			Username: env.GetEmailUsername(),
			Password: env.GetEmailPassword(),
			Host:     env.GetEmailHost(),
			Port:     emailPort,
		},

		ESPod: &data.PodInfo{
			PVC:      elasticOpts.PVC,
			Pod:      elasticOpts.Pod,
			DataPath: elasticOpts.DataPath,
		},

		RDBPod: &data.PodInfo{
			PVC:       rdbOpts.PVC,
			Pod:       rdbOpts.Pod,
			DataPath:  rdbOpts.DataPath,
			Container: rdbOpts.Container,
		},
	})
	if err != nil {
		logging.Get().Err(err).Msgf("ERROR: DataService init error")
	}

	rlErr := assetsSvc.InitResourcesService(rdb, scannerURL)
	if rlErr != nil {
		logging.Get().Err(rlErr).Msg("ERROR: InitResourcesService init error")
	}

	ucErr := usercenter.Init(rdb)
	if ucErr != nil {
		logging.Get().Err(ucErr).Msg("ERROR: usercenter limiter init error")
	}

	// scap service
	err = sp.Init(mainCtx, scapOpts, redisClient, rdb)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: scapService  init error")
	}

	// cron service
	c := cr.New()
	c.Start()
	err = cron.Init(c, rdb)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: cronService  init error")
	}

	reErr := riskexplorer.Init(scannerURL, redisClient)
	if reErr != nil {
		logging.Get().Err(reErr).Msg("ERROR: riskexplorerService init error")
	}

	// networkTopo service
	ntErr := networktopo.Init(rdb)
	if ntErr != nil {
		logging.Get().Err(ntErr).Msg("ERROR: networkFlowService init error")
	}

	err = attck.Init(rdb, redisClient, ecenterCli)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: config service init error")
	}

	err = k8saudit.Init(rdb, es)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: k8s-audit service init error")
	}

	err = openapiauth.Init(rdb, redisClient)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: openapi auth service init error")
		mainCancel()
		return nil, err
	}

	err = hunter.Init(rdb)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: hunter service init error")
	}

	err = captcha.Init(redisClient, captcha.DefaultConf)
	if err != nil {
		logging.Get().Err(ntErr).Msg("ERROR: captcha service init error")
		mainCancel()
		return nil, err
	}

	err = session.Init(redisClient, session.DefaultConf)
	if err != nil {
		logging.Get().Err(ntErr).Msg("ERROR: session service init error")
		mainCancel()
		return nil, err
	}

	err = apiscan.Init(rdb)
	if err != nil {
		logging.Get().Err(ntErr).Msgf("ERROR: apiscan service init error")
	}
	err = platformreport.Init(rdb, &def.EmailConf{
		Username: env.GetEmailUsername(),
		Password: env.GetEmailPassword(),
		Host:     env.GetEmailHost(),
		Port:     emailPort,
	})
	if err != nil {
		logging.Get().Err(ntErr).Msg("ERROR: platform report service init error")
	}

	// init cluster manager
	kubeConfig, err := k8s.KubeConfig()
	if err != nil {
		mainCancel()
		return nil, err
	}
	clientset, err := assets.NewForConfig(kubeConfig)
	if err != nil {
		mainCancel()
		return nil, err
	}
	err = k8s.InitClusterManager(clientset, nil, clusterManagerURL)
	if err != nil {
		logging.Get().Err(err).Msg("cluster manager init error")
		mainCancel()
		return nil, err
	}

	err = processingcenter.Init(&processingcenter.ServiceComponent{
		DB:              rdb,
		EsCli:           es,
		RedisCli:        redisClient,
		MicroSegBaseURL: microsegURL,
	})
	if err != nil {
		logging.Get().Err(err).Msg("init process center error")
	}

	err = defense.InitDefenseService(rdb, ecBuzCli, scannerURL)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: bait service init error")
	}

	return &Console{
		server: &http.Server{
			Addr: httpOpts.HTTPListen,
			Handler: setupChiRouter(
				mainCtx,
				rdb,
				es,
				scannerURL,
				fmt.Sprintf("http://%s:%d", secProfilesOpts.Host, secProfilesOpts.Port),
				microsegURL,
				env.GetWebHookUrl(),
				httpOpts.HTTPLoggerDisabled,
				redisClient,
				nil, //harborClient,
				ecBuzCli,
			),
		},
		webHookServer: &http.Server{Addr: httpOpts.HTTPWebHookListen, Handler: setupWebHookRouter()},
		rdb:           rdb,
		es:            es,
		cancel:        mainCancel,
		harborClient:  nil, //harborClient,
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
				logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		defer wg.Done()
		if err := c.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				logging.Get().Error().Err(err).Msg("error in http.Server.ListenAndServe")
			}
		}
	}()
	// webhook
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		defer wg.Done()
		if err := c.webHookServer.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				logging.Get().Error().Err(err).Msg("error in http.Server.ListenAndServe")
			}
		}
	}()

	ctx, mcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer mcancel()

	//testCtx, testCancel := context.WithTimeout(ctx, time.Second*10)
	//defer testCancel()
	//canDowngrade := true
	//err := c.harborClient.TestConnectionAndAdminPrivileges(testCtx, canDowngrade)
	//if err != nil {
	//	logging.Get().Error().Err(err).Msg("Harbor connection and admin privilege check failed")
	//}

	err := rdbCheck(c.rdb.Get())
	if err != nil {
		logging.Get().Err(err).Msg("When check admin data in postgres")
	}

	clusterManager, ok := k8s.GetClusterManager()
	if ok {
		clusterManager.Start()
	} else {
		logging.Get().Error().Err(errors.New("cluster manager not exist")).Msg("get a nil cluster manager")
	}

	cronService, _ := cron.Get(ctx)
	err = cronService.StartCrons(ctx)
	if err != nil {
		logging.Get().Error().Err(err).Msg("When starting cron jobs")
	}

	scapper, _ := scapper.GetScapper(ctx)
	err = scapper.InitCheckUnFinishedJobs(ctx)
	if err != nil {
		logging.Get().Error().Err(err).Msg("When scapper InitCheckUnFinishedJobs")
	}

	logging.Get().Info().Msg("TensorNavigator started")

	return func() {
		c.cancel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.server.Shutdown(ctx); err != nil {
			logging.Get().Error().Err(err).Msg("Error in shutting down HTTP server")
		}
		wg.Wait()

		logging.Get().Info().Msg("TensorNavigator stopped")
	}
}

const (
	postgreCheckTimeout = time.Minute
)

func rdbCheck(db *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgreCheckTimeout)
	defer cancel()
	queryUser := model.User{}
	err := db.WithContext(ctx).Where("username = ?", model.UserSuperAdmin).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		salt := dal.RandStringBytesMaskImprSrcUnsafe(8)
		hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(model.PasswordSuperAdmin+salt)))
		user := model.User{UserName: model.UserSuperAdmin, Checked: true, CreatedAt: time.Now().Unix(), Rule: model.RoleSuperAdmin, Salt: salt, Pwd: hashPwd}
		authToken := util.GenerateUUIDHex()
		err = db.Transaction(func(tx *gorm.DB) error {
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
		if err = db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).Create(module).Error; err != nil {
			logging.Get().Err(err).Msgf("init module:%s fail", module.ModuleNameEn)
			return err
		}
	}

	url1 := model.Url{Id: 1, UrlName: "/api/v2/usercenter", UrlId: mg1.Id}
	url2 := model.Url{Id: 2, UrlName: "/api/v2/platform", UrlId: mg2.Id}
	url3 := model.Url{Id: 3, UrlName: "/api/v2/containerSec", UrlId: mg3.Id}
	url4 := model.Url{Id: 4, UrlName: "/api/v2/microseg", UrlId: mg4.Id}

	urls := []*model.Url{&url1, &url2, &url3, &url4}
	for _, url := range urls {
		if err = db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).Create(url).Error; err != nil {
			logging.Get().Err(err).Msgf("init url:%s fail", url.UrlName)
			return err
		}
	}

	return nil
}

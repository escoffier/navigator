package service

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/configs"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/iac"
	"gitlab.com/security-rd/go-pkg/translate"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/apiscan"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/attck"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cmcc"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/containers"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/defense"
	drvSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/drift"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/hunter"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/idp"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/imagesec"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/immune"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/k8saudit"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/license"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/naviaudit"
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
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/waf"
	"gitlab.com/piccolo_su/vegeta/cmd/data/notifyhandler"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/redisearch"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"k8s.io/apimachinery/pkg/util/wait"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
)

const resyncInterval = 8 * time.Hour

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
	exporterOpts *flag.ExporterOpts,
	scapOpts *flag.ScapOpts,
	elasticOpts *flag.ElasticOpts,
	rdbOptions *databases.Options,
) (*Console, error) {
	// Redis DB client
	redisClient, err := cache.NewRedis()
	if err != nil {
		return nil, err
	}

	rdb, err := databases.NewRDBClient(rdbOptions)
	if err != nil {
		logging.Get().Err(err).Msg("Init DB error")
		return nil, err
	}

	scannerURL := fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port)
	exportURL := fmt.Sprintf("http://%s:%d", exporterOpts.Host, exporterOpts.Port)
	microsegURL := os.Getenv("MICROSEG_URL")
	sherlockURL := os.Getenv("SHERLOCK_URL")
	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	myPodName := os.Getenv("MY_POD_NAME")
	clusterManagerURL := env.GetClusterManagerUrl()

	sherlockClient := echelper.NewSherlockClient(sherlockURL)

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// harbor client for tensor harbor adapter
	// temperately comment,need refactor
	// harborClient, err := harbor.NewHarborRESTClient(mainCtx, harborOpts)
	// if err != nil {
	//	logging.Get().Error().Msg(fmt.Sprintf("ERROR: harbor client init error :%s ", err))
	// }

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

	mqFactory := mq.GetClientFactory()
	mqReader, err := mqFactory.Reader(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("init mq reader error")
		panic(err)
	}

	var redisearchClient *redisearch.Client

	if os.Getenv("USE_REDISEARCH") != "false" {
		redisearchClient, err = redisearch.NewClient()
		if err != nil {
			return nil, err
		}
		err = redisearchClient.RegisterClient(context.Background(), "pod", "resource", "rawContainer")
		if err != nil {
			return nil, err
		}

	}
	// stream
	stream := rpcstream.NewStreamFactory(rpcstream.WithClusterKey("main")).Server("tcp", ":19090")
	_ = stream.AddHandler(&pb.ClusterRegister{}, &assetsSvc.ClustertHandler{
		DB: rdb,
	})
	_ = stream.AddHandler(&pb.ImageSecReq{}, &imagesec.StreamHandler{
		ServerStream: stream,
	})
	err = stream.Start()
	if err != nil {
		// log but not exit
		logging.Get().Err(err).Msg("failed to start grpc server")
	}
	// scap service
	err = sp.Init(mainCtx, sp.EnvironmentInfo{
		MyNamespace: myNamespace,
		MyPodName:   myPodName,
	}, scapOpts, redisClient, rdb, stream, mqReader)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: scapService  init error")
	}

	rlErr := assetsSvc.InitResourcesService(rdb, redisearchClient, scannerURL, stream)
	if rlErr != nil {
		logging.Get().Err(rlErr).Msg("ERROR: InitResourcesService init error")
	}

	resSvc, ok := assetsSvc.GetResourcesService(mainCtx)
	if !ok {
		logging.Get().Panic().Msg("init GetResourcesService fails")
	}

	ucErr := usercenter.Init(rdb)
	if ucErr != nil {
		logging.Get().Err(ucErr).Msg("ERROR: usercenter limiter init error")
	}

	reErr := riskexplorer.Init(scannerURL, redisClient, sherlockClient)
	if reErr != nil {
		logging.Get().Err(reErr).Msg("ERROR: riskexplorerService init error")
	}

	// networkTopo service
	ntErr := networktopo.Init(rdb)
	if ntErr != nil {
		logging.Get().Err(ntErr).Msg("ERROR: networkFlowService init error")
	}

	err = attck.Init(rdb, redisClient, sherlockClient)
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

	err = hunter.Init(myPodName, myNamespace, rdb)
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

	err = idp.InitIdpLogin(rdb, redisClient)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: thirdLogin service init error")
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

	err = waf.InitWafService(rdb, sherlockClient, myNamespace)
	if err != nil {
		logging.Get().Err(err).Msg("waf service init error")
	}

	if os.Getenv("TENSOR_CLIENT_PLATFORM") == cmcc.CMUserPlatform {
		// 中移SSO用户关系
		cmOpt, err := cmcc.GetCMUserOption()
		if err != nil {
			logging.Get().Err(err).Msg("ERROR: read ChinaMobile env option error")
			mainCancel()
			return nil, err
		}
		// 初始化
		cm, err := cmcc.InitCMUserService(rdb, cmOpt.Appid, cmOpt.APIHost, cmOpt.APIKey, cmOpt.AuthKey)
		if err != nil {
			logging.Get().Err(err).Msg("ERROR: init ChinaMobile service error")
			mainCancel()
			return nil, err
		}

		// mainCancel will be called on error, so we don't need to call the child cancel
		cmCtx, _ := context.WithTimeout(mainCtx, 30*time.Second)

		err = cm.StartSubscribeCMUserMsg(cmCtx, cmOpt.PulsarURL)
		if err != nil {
			logging.Get().Err(err).Msg("ERROR: sync and handle cm user event error")
			mainCancel()
			return nil, err
		}
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

	factory := externalversions.NewSharedInformerFactory(clientset.TensorClientset, resyncInterval)
	err = k8s.InitClusterManager(clientset, factory, clusterManagerURL)
	if err != nil {
		logging.Get().Err(err).Msg("cluster manager init error")
		mainCancel()
		return nil, err
	}

	clusterManager, _ := k8s.GetClusterManager()
	err = processingcenter.Init(&processingcenter.ServiceComponent{
		DB:              rdb,
		EsCli:           es,
		ClusterManager:  clusterManager,
		MicroSegBaseURL: microsegURL,
	})
	if err != nil {
		logging.Get().Err(err).Msg("init process center error")
	}

	drErr := drvSvc.InitDriftService(rdb, es, mqReader)
	if drErr != nil {
		logging.Get().Err(drErr).Msg("ERROR: InitDriftService init error")
	}

	err = defense.InitDefenseService(rdb, es, scannerURL, stream)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: bait service init error")
	}

	err = license.Init(rdb)
	if err != nil {
		logging.Get().Error().Err(err).Msg("ERROR: license init error")
		mainCancel()
		return nil, err
	}

	err = naviaudit.InitService(es, rdb)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: navi-audit service init error")
	}

	exportContainers := os.Getenv("EXPORT_CONTAINERS")
	if exportContainers == "true" {
		cntErr := containers.InitContainersService(rdb, scannerURL)
		if cntErr != nil {
			logging.Get().Err(cntErr).Msg("ERROR: InitContainersService init error")
		}
	}

	err = configs.Init(rdb, redisClient)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: configs service init error")
	}

	// init iac-yaml scan
	logging.Get().Debug().Msg("start NewYamlScanner")
	err = iac.NewYamlScanner(rdb.Get())
	if err != nil {
		logging.Get().Error().Err(err).Msg("ERROR: YamlScanner init error")
		mainCancel()
		return nil, err
	}
	logging.Get().Debug().Msg("end NewYamlScanner")

	// init iac-dockerfile
	logging.Get().Debug().Msg("start NewDockerfile")
	err = iac.NewDockerfile(rdb.Get())
	if err != nil {
		logging.Get().Error().Err(err).Msg("ERROR: Dockerfile init error")
		mainCancel()
		return nil, err
	}
	logging.Get().Debug().Msg("end NewDockerfile")

	translation, err := translate.NewTranslation(mainCtx, rdb)
	if err != nil {
		logging.Get().Error().Err(err).Msg("ERROR: translation init error")
		mainCancel()
		return nil, err
	}

	return &Console{
		server: &http.Server{
			Addr: httpOpts.HTTPListen,
			Handler: setupChiRouter(
				mainCtx,
				rdb,
				es,
				scannerURL,
				exportURL,
				sherlockURL,
				microsegURL,
				env.GetWebHookUrl(),
				httpOpts.HTTPLoggerDisabled,
				httpOpts.HTTPAuditDisabled,
				sherlockClient,
				redisClient,
				nil, // harborClient,
				translation,
				clusterManager,
				resSvc,
			),
		},
		webHookServer: &http.Server{Addr: httpOpts.HTTPWebHookListen, Handler: setupWebHookRouter()},
		rdb:           rdb,
		es:            es,
		cancel:        mainCancel,
		harborClient:  nil, // harborClient,
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

	clusterManager, ok := k8s.GetClusterManager()
	if ok {
		clusterManager.Start()
		clusterManager.InformerFactory().Start(wait.NeverStop)
		clusterManager.InformerFactory().WaitForCacheSync(wait.NeverStop)
	} else {
		logging.Get().Error().Err(errors.New("cluster manager not exist")).Msg("get a nil cluster manager")
	}

	// 初始化资源同步
	err := iac.SyncResources()
	if err != nil {
		logging.Get().Error().Err(err).Msg("syncResources fails")
	}

	err = rdbCheck(c.rdb.Get())
	if err != nil {
		logging.Get().Err(err).Msg("When check admin data in postgres")
	}

	// cronService, _ := cron.Get(ctx)
	// err = cronService.StartCrons(ctx)
	// if err != nil {
	// 	logging.Get().Error().Err(err).Msg("When starting cron jobs")
	// }

	driftService, ok := drvSvc.GetDriftService(ctx)
	if ok {
		err = driftService.Start()
		if err != nil {
			logging.Get().Error().Err(err).Msg("When starting drift service")
		}
	} else {
		logging.Get().Error().Err(errors.New("drift service not exist")).Msg("get a nil drift service")
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
		if err := c.webHookServer.Shutdown(ctx); err != nil {
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
		if err := db.WithContext(ctx).Clauses(clause.OnConflict{
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
		if err := db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).Create(url).Error; err != nil {
			logging.Get().Err(err).Msgf("init url:%s fail", url.UrlName)
			return err
		}
	}

	return nil
}

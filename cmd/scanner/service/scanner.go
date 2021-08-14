package service

import (
	"context"
	"fmt"
	logg "log"
	"net/http"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/mattn/go-colorable"
	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	layerManage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/layer_manage"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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
	server          *http.Server
	ginServer       *http.Server
	redclair        *component.RedClairService
	viursScan       *component.VirusScan
	mongoClient     *mongo.Database
	ctx             context.Context
	cancel          context.CancelFunc
	localLayerMange *layerManage.LocalLayerManageSrv
	postgresDB      *store.ScannerDB
	harborOpts      *flag.HarborOpts
	globalCache     *cache.Cache
}

// NewScanner is to create a new Scanner struct.
func NewScanner(
	httpOpts *flag.HTTPOpts,
	mongoOpts *flag.MongoOpts,
	clairOpts *flag.ClairOpts,
	redisOpts *flag.RedisOpts,
	updateOpts *flag.UpdateOpts,
	harborOpts *flag.HarborOpts,
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
	// postgres

	postgresDB, err := rdbtools.GormWrapperOpen(1*time.Minute, func() (*gorm.DB, error) {
		return gorm.Open(postgres.Open(clairOpts.PostgresConnectionString), &gorm.Config{})
	})

	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
		return nil, err
	}

	if err := postgresDB.Get().AutoMigrate(&model.User{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate user")
	}
	if err := postgresDB.Get().AutoMigrate(&model.Email{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate email")
	}
	if err := postgresDB.Get().AutoMigrate(&model.ImageList{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate tensor_image_list")
	}
	if err := postgresDB.Get().AutoMigrate(&model.QuestionInfo{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate tensor_question ")
	}

	if err := postgresDB.Get().AutoMigrate(&model.ScanImage{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate scan_image")
	}
	if err := postgresDB.Get().AutoMigrate(&model.ScanLayer{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate scan_layer")
	}
	if err := postgresDB.Get().AutoMigrate(&model.VulnImage{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate vuln_image")
	}
	if err := postgresDB.Get().AutoMigrate(&model.Vuln{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate vuln")
	}
	if err := postgresDB.Get().AutoMigrate(&model.Registry{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate registry")
	}
	if err := postgresDB.Get().AutoMigrate(&model.ImageRelate{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate image_relate")
	}
	if err := postgresDB.Get().AutoMigrate(&model.RejectRecord{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate reject_record")
	}
	if err := postgresDB.Get().AutoMigrate(&model.ImageWhitelist{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate image_white_list")
	}
	if err := postgresDB.Get().AutoMigrate(&model.RejectPolicy{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate reject_policy")
	}
	if err := postgresDB.Get().AutoMigrate(&model.RejectVuln{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate reject_vuln")
	}

	scannerDB := store.NewScannerDB(postgresDB)

	// Redis DB client
	sa := strings.Split(redisOpts.Endpoint, ",")
	redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      redisOpts.Password,
		DB:            2,
	})
	if err != nil {
		return nil, err
	}

	// Redis DB1 clinet
	redisClientOne, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      redisOpts.Password,
		DB:            1,
	})
	if err != nil {
		return nil, err
	}

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background()) // nolint govet

	// redclair
	redclairSvc, err := component.NewRedClairService(mainCtx, clairOpts, mongodb, scannerDB, redisClient, updateOpts)
	if err != nil {
		return nil, err // nolint govet
	}

	virusScan, _ := component.NewViursScanService(mainCtx, clairOpts, mongodb, scannerDB, redisClientOne, updateOpts)
	// local layer manage
	llms, err := layerManage.NewLocalLayerManageSrv(mainCtx, "0.0.0.0", 5566, clairOpts.EndpointClairPort, clairOpts.EndpointAddress)
	if err != nil {
		return nil, err // nolint govet
	}

	// harbor client

	// callback cache
	globalCache := cache.New(60*time.Minute, 10*time.Minute)

	return &Scanner{
		ginServer: &http.Server{
			Addr: httpOpts.HTTPListen, Handler: api.SetupGinRouter(
				newConScannerSrv(mongoOpts, clairOpts, redclairSvc, virusScan, globalCache),
				component.NewImageRejectSrc(store.NewScannerOrm(postgresDB)),
				component.NewHarborSrc(store.NewScannerOrm(postgresDB), redisClient, redclairSvc),
			),
		},
		globalCache:     globalCache,
		postgresDB:      scannerDB,
		redclair:        redclairSvc,
		viursScan:       virusScan,
		mongoClient:     mongodb,
		ctx:             mainCtx,
		cancel:          mainCancel,
		localLayerMange: llms,
		harborOpts:      harborOpts,
	}, nil
}

// Run is to run the service.
func (s *Scanner) Run() func() {
	log.Info().Msg("Vegeta ScannerApi started")
	cmd := exec.Command("service", "clamav-daemon", "start") // start clamd service
	if _, err := cmd.Output(); err != nil {
		logging.GetLogger().Err(err).Msg("Run Server cmd.Output error")
	}
	s.postgresDB.FailInProgressStatus(context.Background())
	var wg sync.WaitGroup

	// start NewSyncRepoImage service
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("start Layer NewSyncRepoImage error : %v. stack: %s", r, debug.Stack())
				panic(r)
			}
		}()

		defer wg.Done()
		r, err := component.NewSyncRepoImage(s.ctx, s.harborOpts.ConfigPath, uint(s.harborOpts.SyncInterval), s.postgresDB)
		var wg sync.WaitGroup
		for i := range r {
			wg.Add(1)
			tmp := r[i]
			go tmp.Run(func(image registry.Image) error { // nolint: errcheck
				transImagelist := component.TransImageToImagelist(tmp, image)
				if _, err := s.postgresDB.InsertImageList(context.Background(), transImagelist); err != nil {
					return err
				}
				return nil
			}, &wg)
		}
		wg.Wait()
		if err != nil {
			log.Panic().
				Err(err).
				Msg("Panic failed to start local layer manage server")
		}
	}()
	// image.NewImageService(s.postgresDB, s.harborClient)

	// start reject cache
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("start Layer Manage scanner error : %v. stack: %s", r, debug.Stack())
				panic(r)
			}
		}()

		defer wg.Done()
		ticker := time.NewTicker(time.Minute * 1)
		for {
			<-ticker.C
			s.checkGlobalCache(s.globalCache)
		}
	}()

	// start local layer manage
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("start Layer Manage scanner error : %v. stack: %s", r, debug.Stack())
				panic(r)
			}
		}()

		defer wg.Done()
		err := s.localLayerMange.Run()
		if err != nil {
			log.Panic().
				Err(err).
				Msg("Panic failed to start local layer manage server")
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Htpp.Server error : %v. stack: %s", r, debug.Stack())
				panic(r)
			}
		}()

		defer wg.Done()
		if err := s.ginServer.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Panic().Err(err).Msg("Panic in http.Server.ListenAndServe")
			}
		}
	}()

	// start clair scanner
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Clair error : %v. stack: %s", r, debug.Stack())
				panic(r)
			}
		}()

		defer wg.Done()
		err := s.redclair.Run(s.ctx, s.localLayerMange)
		if err != nil {
			log.Panic().Err(err).Msg("Panic failed to start redclair")
		}
	}()

	// start virus scanner
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("ViursScan error : %v. stack: %s", r, debug.Stack())
				panic(r)
			}
		}()

		defer wg.Done()
		err := s.viursScan.Run(s.ctx, s.localLayerMange)
		if err != nil {
			log.Panic().Err(err).Msg("Panic failed to start ViursScan")
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
		if err := s.ginServer.Shutdown(ctx); err != nil {
			log.Error().
				Err(err).
				Msg("error in shutting down Gin HTTP server")
		}

		wg.Wait()

		log.Info().Msg("Vegeta ScannerApi stopped")
	}
}

func newConScannerSrv(
	mongoOpts *flag.MongoOpts,
	opts *flag.ClairOpts,
	redclair *component.RedClairService,
	virusScan *component.VirusScan,
	globalCache *cache.Cache,
) component.ScannerSrv {

	mongoString := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=%s", mongoOpts.Username, mongoOpts.Password, mongoOpts.Endpoint, mongoOpts.Database)
	mongoClientOptions := options.Client().ApplyURI(mongoString)
	mongoClientOptions.SetWriteConcern(writeconcern.New(writeconcern.WMajority()))
	mongoClientOptions.SetReadConcern(readconcern.Majority())
	mongoClient, err := mongo.NewClient(mongoClientOptions)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mongoClient.Connect(ctx); err != nil {
		panic(err)
	}

	newLogger := logger.New(
		logg.New(colorable.NewColorableStdout(), "\r\n", logg.LstdFlags),
		logger.Config{
			SlowThreshold: time.Second,
			LogLevel:      logger.Info,
			Colorful:      true,
		},
	)
	// postsql
	db, err := rdbtools.GormWrapperOpen(1*time.Minute, func() (*gorm.DB, error) {
		return gorm.Open(postgres.Open(opts.PostgresConnectionString), &gorm.Config{Logger: newLogger})
	})
	if err != nil {
		// 数据库在初始化时都出错，就应该直接panic
		panic(err)
	}
	sqlDB, err := db.Get().DB()
	if err != nil {
		panic(fmt.Sprintf("get DB error %s", err.Error()))
	}
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(30)
	sqlDB.SetConnMaxLifetime(time.Hour)
	dal := store.NewScannerOrm(db)

	srv := component.NewConScannerSrv(dal, redclair, virusScan, store.NewScannerDB(db), globalCache)
	go srv.DeleteCICDImage(context.Background()) // 起协程删除cache仓库的image
	return srv
}

func (s *Scanner) checkGlobalCache(cache *cache.Cache) {
}

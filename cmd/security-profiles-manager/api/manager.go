package api

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"net/http"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"

	"github.com/go-redis/redis/v8"
	"github.com/nats-io/nats.go"
	stan "github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/builder"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/falco"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/policy"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/profile"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/queue"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/resource"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	log *logging.Logger
)

const (
	defaultK8sClusterName = "default"
)

func init() {
	log = logging.GetLogger()
}

// SecProfileManager represents the Vegeta Security Profile Manager server.
type SecProfileManager struct {
	lifecycle.Service
	server *http.Server
	ctx    context.Context
	cancel context.CancelFunc
}

// NewSecProfileManager is to create a new SecProfileManager struct.
func NewSecProfileManager(
	httpOpts *flag.HTTPOpts,
	redisOpts *flag.RedisOpts,
	stanOpts *flag.StanOpts,
	postgresOpts *flag.PostgresOpts,
) (*SecProfileManager, error) {

	db, err := rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
		db, err := gorm.Open(postgres.Open(postgresOpts.PostgresConnectionString), &gorm.Config{})
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

	db.Get().AutoMigrate(&model.SecurityPolicy{})
	db.Get().AutoMigrate(&model.SecurityPolicyResource{})
	db.Get().AutoMigrate(&model.ApparmorProfile{})
	db.Get().AutoMigrate(&model.SeccompProfile{})
	db.Get().AutoMigrate(&model.CommandWhitelistProfile{})
	db.Get().AutoMigrate(&model.DriftProfile{})
	db.Get().AutoMigrate(&model.ApparmorProfileData{})
	db.Get().AutoMigrate(&model.SeccompProfileData{})
	db.Get().AutoMigrate(&model.CommandWhitelistProfileData{})

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

	nc, err := nats.Connect(
		fmt.Sprintf("nats://%s", stanOpts.URL),
		nats.MaxReconnects(-1),
		nats.ReconnectBufSize(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to connect to NATS MQ")
		return nil, err
	}
	sc, err := stan.Connect(stanOpts.ClusterID, stanOpts.ClientID, stan.NatsConn(nc))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to connect to STAN MQ")
		return nil, err
	}

	var config *rest.Config
	config, err = rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// security policy service
	err = profile.Init(db, clientset)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to init profile service")
		return nil, err
	}

	// security policy service
	err = policy.Init(db, clientset)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to init policy service")
		return nil, err
	}

	// queue service
	err = queue.Init(mainCtx, &sc, clientset, redisClient, db)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to init queue service")
		return nil, err
	}

	// security profile builder service
	err = builder.Init(mainCtx, db, redisClient, clientset)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to init builder service")
		return nil, err
	}

	// security resource service
	err = resource.Init(mainCtx, db, clientset)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to init resource service")
		return nil, err
	}
	resourceService, exists := resource.Get()
	if !exists {
		logging.GetLogger().Error().Err(err).Msg("Failed to get resource service")
		return nil, fmt.Errorf("Failed to get resource service")
	}
	go resourceService.Init()

	// falco service
	err = falco.Init(db, clientset)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to init falco service")
		return nil, err
	}

	return &SecProfileManager{
		server: &http.Server{
			Addr: httpOpts.HTTPListen,
			Handler: setupChiRouter(
				mainCtx,
			),
		},
		ctx:    mainCtx,
		cancel: mainCancel,
	}, nil
}

// Run is to run the service.
func (m *SecProfileManager) Run() func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := m.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Error().
					Err(err).
					Msg("error in http.Server.ListenAndServe")
			}
		}
	}()

	log.Info().Msg("TensorSecProfileManager started")

	return func() {
		m.cancel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.server.Shutdown(ctx); err != nil {
			log.Error().
				Err(err).
				Msg("Error in shutting down HTTP server")
		}
		wg.Wait()

		log.Info().Msg("TensorsSecProfileManager stopped")
	}
}

package api

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/builder"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/falco"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/policy"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/profile"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/queue"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/resource"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/databases"
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

var runes = []rune{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
}

func getClientID(name string) string {
	b := strings.Builder{}
	for _, by := range name {
		if (by >= 'a' && by <= 'z') || (by >= 'A' && by <= 'Z') || (by >= '0' && by <= '9') || by == '-' || by == '_' {
			b.WriteRune(by)
		} else {
			b.WriteRune(runes[rand.Intn(len(runes))])
		}
	}
	b.WriteRune('_')
	randNum := 5 + rand.Intn(5)
	for i := 0; i < randNum; i++ {
		b.WriteRune(runes[rand.Intn(len(runes))])
	}
	return b.String()
}

// NewSecProfileManager is to create a new SecProfileManager struct.
func NewSecProfileManager(httpOpts *flag.HTTPOpts, stanOpts *flag.StanOpts) (*SecProfileManager, error) {
	podName := os.Getenv("MY_POD_NAME")
	rdbUser := os.Getenv("RDB_USER")
	rdbPassword := os.Getenv("RDB_PASSWORD")
	rdbHost := os.Getenv("RDB_HOST")
	rdbPort := os.Getenv("RDB_PORT")
	rdbDBName := os.Getenv("RDB_DBNAME")
	rdbSSLMode := os.Getenv("RDB_SSLMODE")
	if rdbUser == "" || rdbPassword == "" || rdbHost == "" || rdbPort == "" || rdbSSLMode == "" || rdbDBName == "" {
		return nil, errors.New("missing RDB env")
	}

	db, err := databases.NewRDBWithMySQLByEnv(context.Background())
	if err != nil {
		logging.GetLogger().Err(err).Msg("Init postgre error")
		return nil, err
	}

	// Redis DB client
	redisClient, err := cache.NewRedis()
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
	sc, err := stan.Connect(stanOpts.ClusterID, getClientID(podName), stan.NatsConn(nc))
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

	// log.Info().Msg("TensorSecProfileManager started")
	log.Info().Msg("ProfileManager started")

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

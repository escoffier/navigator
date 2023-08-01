package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	preinit "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/pre-init"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

// Scanner represents the Vegeta Scanner server.
type Scanner struct {
	lifecycle.Service
	PodID           string // uuid
	options         *flag2.ScannerOpts
	servicesList    map[string]register.ScannerService // save all scanner service
	ScannerInstance string
	ClusterKey      string
	ClusterName     string
}

type ClusterKey struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

func GetCluster(ctx context.Context) (ClusterKey, error) {
	if os.Getenv("LOCAL_DEBUG") == consts.TrueString {
		return ClusterKey{}, nil
	}

	clusterURL := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterURL == "" {
		return ClusterKey{}, fmt.Errorf("not get CLUSTER_MANAGER_URL")
	}
	url := fmt.Sprintf("%s%s", clusterURL, "/internal/cluster")
	timeOutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(timeOutCtx, http.MethodGet, url, nil)
	if err != nil {
		return ClusterKey{}, err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return ClusterKey{}, err
	}
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return ClusterKey{}, err
	}
	cluster := ClusterKey{}

	if err := json.Unmarshal(content, &cluster); err != nil {
		return cluster, err
	}

	return cluster, err
}

// NewScanner is to create a new Scanner struct.
func NewScanner(opts *flag2.ScannerOpts) (*Scanner, error) {
	// init db
	if err := store.InitDb(opts.LogLevel); err != nil {
		logging.Get().Err(err).Msg("connect db failed")
		return nil, err
	}

	// init redis client
	if err := store.InitRedisClient(); err != nil {
		logging.Get().Err(err).Msgf("connect redis failed,%v,%v", opts.RedisPassword, opts.RedisEndpoint)
		return nil, err
	}

	cluster, err := GetCluster(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("GetCluster key")
		return nil, err
	}

	dbInit := preinit.NewInitScanner(store.GetRDBInstance())

	scanner := &Scanner{
		PodID:           uuid.GenerateRandomID(),
		ScannerInstance: fmt.Sprintf("scan-%s", cluster.Key),
		ClusterKey:      cluster.Key,
		ClusterName:     cluster.Name,
		options:         opts,
		servicesList:    make(map[string]register.ScannerService),
	}

	if err := dbInit.Init(context.Background()); err != nil {
		logging.Get().Err(err).Msg("db init policy err")
		return nil, err
	}

	return scanner, nil
}

// Run is to run the service.
func (s *Scanner) Run() func() {
	logging.Get().Info().Msg("scanner started")

	// create all register services
	s.CreateService()

	// start all service
	s.StartServices()

	return func() {

		s.StopServices(context.Background())

		logging.Get().Info().Msg("scanner stopped")
	}
}

func (s *Scanner) CreateService() {
	ss := register.GetServices()
	for k := range ss {
		config := register.ScannerServiceConfig{
			Type:    k,
			Options: s.options,
		}
		srv, err := register.Open(config)
		if err != nil {
			logging.Get().Err(err).Str("type", k).Msg("create service err")
			continue
		}
		logging.Get().Info().Str("type", k).Msg("create service ok")
		s.servicesList[k] = srv
	}

	logging.Get().Info().Msg("all service created")
}

func (s *Scanner) StartServices() {
	// s.DumpServices()
	for name := range s.servicesList {
		go func(serviceName string) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("scanner service panic : %v. stack: %s", r, debug.Stack())
				}
			}()

			logging.Get().Info().Str("serviceName", serviceName).Msg("scanner service ready to start")
			err := s.servicesList[serviceName].Start(context.Background())
			if err != nil {
				logging.Get().Err(err).Str("serviceName", serviceName).Msg("scanner service run err")
				return
			}
			logging.Get().Info().Str("serviceName", serviceName).Msg("scanner service start end")
		}(name)
	}

	logging.Get().Info().Msg("all service started")
}

func (s *Scanner) StopServices(ctx context.Context) {
	for name, srv := range s.servicesList {
		err := srv.Stop(ctx)
		if err != nil {
			logging.Get().Err(err).Str("serviceName", name).Msg("scanner service stop err")
		} else {
			logging.Get().Info().Str("serviceName", name).Msg("scanner service stop ok")
		}
	}
}

func (s *Scanner) DumpServices() {
	for name := range s.servicesList {
		logging.Get().Info().Str("serviceName", name).Msg("scanner created service")
	}
}

func (s *Scanner) GetRunningServiceByName(name string) (register.ScannerService, error) {
	v, ok := s.servicesList[name]
	if !ok {
		return nil, fmt.Errorf("not found running service %s", name)
	}
	return v, nil
}

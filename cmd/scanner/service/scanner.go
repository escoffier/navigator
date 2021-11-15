package service

import (
	"context"
	"fmt"
	"runtime/debug"

	"gitlab.com/piccolo_su/vegeta/pkg/uuid"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dequeue"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/engine"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/api"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-sync"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/malicious"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/scanner-vuln"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/task-policy"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/vulnDbUpdate"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/task-check"

	// _ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/ti-update"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/pull-image"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/save-result"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/trivy"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/trivy-srv"
	_ "gitlab.com/piccolo_su/vegeta/pkg/api/apikey"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/harborv1"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/harborv2"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/hwswr"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/jfrog"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
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
	Id           string // uuid
	options      *flag2.ScannerOpts
	servicesList map[string]register.ScannerService // save all scanner service
}

// NewScanner is to create a new Scanner struct.
func NewScanner(opts *flag2.ScannerOpts) (*Scanner, error) {
	// init db
	if err := store.InitDb(opts.DbConnectStr); err != nil {
		log.Error().Err(err).Msg("connect db failed")
		return nil, err
	}

	// init redis client
	if err := store.InitRedisClient(opts.RedisEndpoint, opts.RedisPassword); err != nil {
		log.Error().Err(err).Msg("connect redis failed")
		return nil, err
	}

	// init policy etc
	regDal := store.NewRegistryDao(store.GetScannerWrapperDb())
	imageDal := store.GetScannerOrmDb()

	scanConfigDAl := store.NewScanConfigDao(store.GetScannerWrapperDb())
	dbInit := component.NewInitScanner(regDal, imageDal, scanConfigDAl)
	if err := dbInit.Init(context.Background()); err != nil {
		log.Error().Err(err).Msg("db init policy err")
		return nil, err
	}

	return &Scanner{
		Id:           uuid.GenerateRandomID(),
		options:      opts,
		servicesList: make(map[string]register.ScannerService),
	}, nil
}

// Run is to run the service.
func (s *Scanner) Run() func() {
	log.Info().Msg("scanner started")

	// create all register services
	s.CreateService()

	// start all service
	s.StartServices()

	// start flow engine
	go func() {
		config := engine.SeqEngineConfig{
			DeqType:       "db-dequeue",
			MaxTaskNum:    int64(s.options.ParallelTaskNum),
			MaxSubTaskNum: int64(s.options.ParallelSubTaskNum),
		}
		flowEngine := engine.NewSequenceEngine(config, nil)
		err := flowEngine.Run(context.Background())
		if err != nil {
			log.Error().Err(err).Msg("engine run err")
		}
	}()

	return func() {

		s.StopServices(context.Background())

		log.Info().Msg("scanner stopped")
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
			log.Error().Err(err).Str("type", k).Msg("create service err")
			continue
		}
		log.Info().Str("type", k).Msg("create service ok")
		s.servicesList[k] = srv
	}

	log.Info().Msg("all service created")
}

func (s *Scanner) StartServices() {
	// s.DumpServices()
	for name := range s.servicesList {
		go func(serviceName string) {
			defer func() {
				if r := recover(); r != nil {
					log.Error().Msgf("scanner service error : %v. stack: %s", r, debug.Stack())
				}
			}()

			log.Info().Str("serviceName", serviceName).Msg("scanner service ready to start")
			err := s.servicesList[serviceName].Start(context.Background())
			if err != nil {
				log.Error().Err(err).Str("serviceName", serviceName).Msg("scanner service run err")
			}
		}(name)
	}

	log.Info().Msg("all service started")
}

func (s *Scanner) StopServices(ctx context.Context) {
	for name, srv := range s.servicesList {
		err := srv.Stop(ctx)
		if err != nil {
			log.Error().Err(err).Str("serviceName", name).Msg("scanner service stop err")
		} else {
			log.Info().Str("serviceName", name).Msg("scanner service stop ok")
		}
	}
}

func (s *Scanner) DumpServices() {
	for name := range s.servicesList {
		log.Info().Str("serviceName", name).Msg("scanner created service")
	}
}

func (s *Scanner) GetRunningServiceByName(name string) (register.ScannerService, error) {
	v, ok := s.servicesList[name]
	if !ok {
		return nil, fmt.Errorf("not found running service %s", name)
	}
	return v, nil
}

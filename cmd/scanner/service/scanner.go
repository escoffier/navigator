package service

import (
	"context"
	"fmt"
	"runtime/debug"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/engine"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

// Scanner represents the Vegeta Scanner server.
type Scanner struct {
	lifecycle.Service
	ID           string // uuid
	options      *flag2.ScannerOpts
	servicesList map[string]register.ScannerService // save all scanner service
}

// NewScanner is to create a new Scanner struct.
func NewScanner(opts *flag2.ScannerOpts) (*Scanner, error) {
	// init db
	if err := store.InitDb(opts.LogLevel); err != nil {
		logging.Get().Error().Err(err).Msg("connect db failed")
		return nil, err
	}

	// init redis client
	if err := store.InitRedisClient(opts.RedisEndpoint, opts.RedisPassword); err != nil {
		logging.Get().Error().Err(err).Msgf("connect redis failed,%v,%v", opts.RedisPassword, opts.RedisEndpoint)
		return nil, err
	}

	// init policy etc
	regDal := store.NewRegistryDao(store.GetScannerWrapperDb())
	imageDal := store.GetScannerOrmDb()

	scanConfigDAl := store.NewScanConfigDao(store.GetScannerWrapperDb())
	dbInit := component.NewInitScanner(regDal, imageDal, scanConfigDAl)
	if err := dbInit.Init(context.Background()); err != nil {
		logging.Get().Err(err).Msg("db init policy err")
		return nil, err
	}

	return &Scanner{
		ID:           uuid.GenerateRandomID(),
		options:      opts,
		servicesList: make(map[string]register.ScannerService),
	}, nil
}

// Run is to run the service.
func (s *Scanner) Run() func() {
	logging.Get().Info().Msg("scanner started")

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
			logging.Get().Error().Err(err).Msg("engine run err")
		}
	}()

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
			logging.Get().Error().Err(err).Str("type", k).Msg("create service err")
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
				logging.Get().Error().Err(err).Str("serviceName", serviceName).Msg("scanner service run err")
			}
		}(name)
	}

	logging.Get().Info().Msg("all service started")
}

func (s *Scanner) StopServices(ctx context.Context) {
	for name, srv := range s.servicesList {
		err := srv.Stop(ctx)
		if err != nil {
			logging.Get().Error().Err(err).Str("serviceName", name).Msg("scanner service stop err")
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

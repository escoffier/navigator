package service

import (
	"context"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/flag"
	preinit "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/preInit"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

// Scanner represents the Vegeta Scanner server.
type Scanner struct {
	lifecycle.Service
	PodID        string // uuid：
	WG           sync.Locker
	options      *flag2.ScannerOpts
	servicesList map[string]register.ScannerService // save all scanner service
	Log          *scannerUtils.LogEvent
}

type ClusterKey struct {
	Key  string `json:"key"`
	Name string `json:"name"`
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
		logging.Get().Err(err).Msgf("connect redis failed")
		return nil, err
	}

	dbInit := preinit.NewInitScanner(store.GetRDBInstance())

	scanner := &Scanner{
		WG:           &sync.Mutex{},
		PodID:        uuid.GenerateRandomID(),
		options:      opts,
		servicesList: make(map[string]register.ScannerService),
		Log:          scannerUtils.NewLogEvent(scannerUtils.WithModule("NewScanner")),
	}

	if err := dbInit.Init(context.Background()); err != nil {
		scanner.Log.Err(err).Msg("can not init scanner db data")
		return nil, err
	}

	return scanner, nil
}

// Run is to run the service.
func (s *Scanner) Run() func() {
	s.Log.Info().Msg("scanner started")
	s.CreateAndStartService()

	return func() {

		s.StopServices(context.Background())

		s.Log.Info().Msg("scanner stopped")
	}
}

func (s *Scanner) CreateAndStartService() {
	ss := register.GetServices()
	for name := range ss {
		go func(name string) {

			defer func() {
				if r := recover(); r != nil {
					s.Log.Error().Msgf("scanner service panic : %v. stack: %s", r, debug.Stack())
				}
			}()

			config := register.ScannerServiceConfig{
				Type:    name,
				Options: s.options,
			}
			for {
				srv, err := register.Open(config)
				if err != nil {
					s.Log.Err(err).Str("type", name).Msg("can not open service")
					time.Sleep(5 * time.Second)
					continue
				}
				if err := srv.Start(context.Background()); err != nil {
					s.Log.Err(err).Str("service", name).Msg("can not start service")
					time.Sleep(5 * time.Second)
					continue
				}
				s.AddService(name, srv)
				break
			}
			s.Log.Info().Str("service", name).Msg("create and start service ok")
		}(name)
	}
}

func (s *Scanner) AddService(name string, srv register.ScannerService) {
	s.WG.Lock()
	defer s.WG.Unlock()
	s.servicesList[name] = srv
}

func (s *Scanner) StopServices(ctx context.Context) {
	for name, srv := range s.servicesList {
		err := srv.Stop(ctx)
		if err != nil {
			s.Log.Err(err).Str("serviceName", name).Msg("scanner service stop err")
		} else {
			s.Log.Info().Str("serviceName", name).Msg("scanner service stop ok")
		}
	}
}

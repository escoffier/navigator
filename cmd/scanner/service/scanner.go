package service

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.etcd.io/etcd/clientv3"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/heartbeat"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
}

const (
	heartbeatEtcdKey = "/agents/%s/pods/scanner/heartbeat"
)

// Scanner represents the Vegeta Scanner server.
type Scanner struct {
	lifecycle.Service
	agentID     string
	server      *http.Server
	etcd        *clientv3.Client
	redclair    *component.RedClair
	mongoClient *mongo.Client
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewScanner is to create a new Scanner struct.
func NewScanner(
	agentID string,
	httpOpts *flag.HTTPOpts,
	etcdOpts *flag.EtcdOpts,
	mongoOpts *flag.MongoOpts,
	clairOpts *flag.ClairOpts,
) (*Scanner, error) {
	// etcd client
	etcd, err := clientv3.New(clientv3.Config{
		Endpoints:   etcdOpts.Endpoints,
		DialTimeout: 5 * time.Second,
		Username:    etcdOpts.Username,
		Password:    etcdOpts.Password,
	})
	if err != nil {
		return nil, err
	}

	// mongo client
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(fmt.Sprintf(
		"mongodb://%s:%s@%s", mongoOpts.Username, mongoOpts.Password, mongoOpts.Endpoint)))
	if err != nil {
		return nil, err
	}
	mongodb := mongoClient.Database(mongoOpts.Database)

	// main function context
	mainCtx, mainCancel := context.WithCancel(context.Background())

	// redclair
	redclair := component.NewRedClair(mainCtx, clairOpts, mongodb)

	return &Scanner{
		agentID: agentID,
		server: &http.Server{
			Addr:    httpOpts.HTTPListen,
			Handler: setupChiRouter(mainCtx, etcd, redclair, mongodb, httpOpts.HTTPLoggerDisabled),
		},
		etcd:        etcd,
		redclair:    redclair,
		mongoClient: mongoClient,
		ctx:         mainCtx,
		cancel:      mainCancel,
	}, nil
}

// Run is to run the service.
func (s *Scanner) Run() func() {
	log.Info().Msg("Vegeta Scanner started")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Error().
					Err(err).
					Msg("error in http.Server.ListenAndServe")
			}
		}
	}()

	// etcd heartbeat
	wg.Add(1)
	go func() {
		defer wg.Done()
		heartbeat.Update(s.ctx, s.etcd, fmt.Sprintf(heartbeatEtcdKey, s.agentID))
	}()

	// start clair scanner
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.redclair.Run(s.ctx)
	}()

	// connect the mongo client
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	err := s.mongoClient.Connect(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in connecting to the Mongo database")
	}

	return func() {
		s.cancel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			log.Error().
				Err(err).
				Msg("error in shutting down HTTP server")
		}
		wg.Wait()

		log.Info().Msg("Vegeta Scanner stopped")
	}
}

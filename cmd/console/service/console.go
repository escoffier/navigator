package service

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v7"
	"go.etcd.io/etcd/clientv3"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
}

// Console represents the Vegeta Console server.
type Console struct {
	lifecycle.Service
	server      *http.Server
	es          *elasticsearch.Client
	etcd        *clientv3.Client
	mongoClient *mongo.Client
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewConsole is to create a new Console struct.
func NewConsole(
	httpOpts *flag.HTTPOpts,
	esOpts *flag.ElasticSearchOpts,
	etcdOpts *flag.EtcdOpts,
	mongoOpts *flag.MongoOpts,
	scannerOpts *flag.VegetaScannerOpts,
) (*Console, error) {
	// elasticsearch client
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: esOpts.URLs,
		Username:  esOpts.Username,
		Password:  esOpts.Password,
		APIKey:    esOpts.APIKey,
	})
	if err != nil {
		return nil, err
	}

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

	return &Console{
		server: &http.Server{
			Addr: httpOpts.HTTPListen,
			Handler: setupChiRouter(
				mainCtx,
				es,
				etcd,
				mongodb,
				fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port),
				httpOpts.HTTPLoggerDisabled,
			),
		},
		es:          es,
		etcd:        etcd,
		mongoClient: mongoClient,
		ctx:         mainCtx,
		cancel:      mainCancel,
	}, nil
}

// Run is to run the service.
func (c *Console) Run() func() {
	log.Info().Msg("Vegeta Console started")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Error().
					Err(err).
					Msg("error in http.Server.ListenAndServe")
			}
		}
	}()

	// etcd watch test example
	wg.Add(1)
	go func() {
		defer wg.Done()
		watchChan := c.etcd.Watch(c.ctx, "/scanner/heartbeat")
		for watchResp := range watchChan {
			for _, event := range watchResp.Events {
				log.Info().
					Str("event_type", event.Type.String()).
					Str("event_kv_key", string(event.Kv.Key)).
					Str("event_kv_value", string(event.Kv.Value)).
					Msg("scanner heartbeat")
			}
		}
	}()

	// connect the mongo client
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	err := c.mongoClient.Connect(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in connecting to the Mongo database")
	}

	return func() {
		c.cancel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.server.Shutdown(ctx); err != nil {
			log.Error().
				Err(err).
				Msg("error in shutting down HTTP server")
		}
		wg.Wait()

		log.Info().Msg("Vegeta Console stopped")
	}
}

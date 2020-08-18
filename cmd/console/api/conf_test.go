package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v7"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/require"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/testing/docker"
	"go.etcd.io/etcd/clientv3"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func setupESClient(t *testing.T,
	f func(w http.ResponseWriter, r *http.Request)) *elasticsearch.Client {
	// disable the log
	logging.Disable()

	if f == nil {
		f = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("{}"))
		}
	}

	// mock ElasticSearch server using httptest
	es := httptest.NewServer(http.HandlerFunc(f))
	esOpts := flag.NewDefaultElasticSearchOpts()
	esOpts.URLs = []string{es.URL}

	esClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: esOpts.URLs,
		Username:  esOpts.Username,
		Password:  esOpts.Password,
		APIKey:    esOpts.APIKey,
	})
	require.NoError(t, err)

	return esClient
}

func setupAPI(
	t *testing.T,
	f func(w http.ResponseWriter, r *http.Request),
	etcdEnabled bool,
	mongoEnabled bool,
) (*api, func() error, func() error) {
	var etcdClient *clientv3.Client
	var etcdTeardown func() error
	if etcdEnabled {
		var etcdPort int
		var err error
		etcdPort, etcdTeardown, err = docker.RunEtcd()
		require.NoError(t, err)

		etcdClient, err = clientv3.New(clientv3.Config{
			Endpoints: []string{fmt.Sprintf("http://localhost:%d", etcdPort)},
		})
		require.NoError(t, err)
	}

	var mongodb *mongo.Database
	var mongoTeardown func() error
	if mongoEnabled {
		var mongoPort int
		var err error
		mongoPort, mongoTeardown, err = docker.RunMongoDB()
		require.NoError(t, err)

		mongoClient, err := mongo.NewClient(options.Client().ApplyURI(
			fmt.Sprintf("mongodb://localhost:%d", mongoPort)))
		require.NoError(t, err)
		mongodb = mongoClient.Database("test")

		// connect
		err = mongoClient.Connect(context.TODO())
		require.NoError(t, err)
	}
	return newAPI(context.TODO(), time.Minute, setupESClient(t, f), etcdClient, mongodb, ""),
		etcdTeardown, mongoTeardown
}

func setupTestServer(t *testing.T) *httptest.Server {
	r := chi.NewRouter()
	SetupRoutes(context.TODO(), r, 500*time.Millisecond, nil, nil, nil, "")
	return httptest.NewServer(r)
}

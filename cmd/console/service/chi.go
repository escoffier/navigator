package service

import (
	"context"
	"net/http"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v7"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"go.etcd.io/etcd/clientv3"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
)

func setupChiRouter(
	ctx context.Context,
	esClient *elasticsearch.Client,
	etcdClient *clientv3.Client,
	mongodb *mongo.Database,
	scapper *api.Scapper,
	scannerURL string,
	httpLoggerDisabled bool,
) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Compress(5))
	r.Use(middleware.Timeout(60 * time.Second))
	if !httpLoggerDisabled {
		r.Use(middleware.Logger)
	}

	api.SetupRoutes(ctx, r, 24*time.Hour, esClient, etcdClient, mongodb, scapper, scannerURL)

	return r
}

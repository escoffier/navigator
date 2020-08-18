package api

import (
	"context"
	"net/http"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v7"
	"github.com/go-chi/jwtauth"
	"github.com/gorilla/securecookie"
	param "github.com/oceanicdev/chi-param"
	"github.com/patrickmn/go-cache"
	"go.etcd.io/etcd/clientv3"
	"go.mongodb.org/mongo-driver/mongo"
)

type api struct {
	ctx        context.Context
	userCache  *cache.Cache
	tokenAuth  *jwtauth.JWTAuth
	esClient   *elasticsearch.Client
	etcdClient *clientv3.Client
	mongodb    *mongo.Database
	scannerURL string
}

func newAPI(
	ctx context.Context,
	sessionExpiration time.Duration,
	esClient *elasticsearch.Client,
	etcdClient *clientv3.Client,
	mongodb *mongo.Database,
	scannerURL string,
) *api {
	return &api{
		ctx:        ctx,
		userCache:  cache.New(sessionExpiration, time.Minute),
		tokenAuth:  jwtauth.New("HS256", securecookie.GenerateRandomKey(64), nil),
		esClient:   esClient,
		etcdClient: etcdClient,
		mongodb:    mongodb,
		scannerURL: scannerURL,
	}
}

func (api *api) getTimeoutCtx(timeout ...time.Duration) (context.Context, context.CancelFunc) {
	if timeout == nil {
		return context.WithTimeout(api.ctx, 10*time.Second)
	}
	return context.WithTimeout(api.ctx, timeout[0])
}

func (api *api) getOffsetAndLimit(r *http.Request) (int64, int64) {
	offset, err := param.QueryUint(r, "offset")
	if err != nil {
		offset = 0
	}
	limit, err := param.QueryUint(r, "limit")
	if err != nil {
		limit = 500
	}
	if limit > 10000 {
		limit = 10000
	}
	return int64(offset), int64(limit)
}

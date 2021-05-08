package api

import (
	"context"
	"github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"go.mongodb.org/mongo-driver/mongo"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
)

type api struct {
	ctx         context.Context
	redclair    *component.RedClairService
	mongodb     *mongo.Database
	redisClient *redis.Client

	// For managing state in Harbor plugin API
	abortAnyNewScansBool           int32
	scanResultLocalBackoffCache    map[string]int // maps scantask ID to last backoff in secs
	scanResultLocalBackoffCacheMux sync.Mutex
	unprocessableEntityCache       *cache.Cache
	harborClient                   *harbor.HarborRESTClient
	virusScan                      *component.VirusScan
}

func newAPI(
	ctx context.Context,
	redclair *component.RedClairService,
	mongodb *mongo.Database,
	harborClient *harbor.HarborRESTClient,
	redisClient *redis.Client,
	virusScan *component.VirusScan,
) *api {
	return &api{
		ctx:      ctx,
		redclair: redclair,
		mongodb:  mongodb,

		scanResultLocalBackoffCache: make(map[string]int),
		unprocessableEntityCache:    cache.New(5*60*time.Second, 60*time.Second),
		harborClient:                harborClient,
		redisClient:                 redisClient,
		virusScan:                   virusScan,
	}
}

package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth"
	"github.com/gorilla/securecookie"
	param "github.com/oceanicdev/chi-param"
	"github.com/patrickmn/go-cache"
	"go.mongodb.org/mongo-driver/mongo"
)

type api struct {
	ctx        context.Context
	userCache  *cache.Cache
	tokenAuth  *jwtauth.JWTAuth
	mongodb    *mongo.Database
	scapper    *Scapper
	scannerURL string
}

func newAPI(
	ctx context.Context,
	sessionExpiration time.Duration,
	mongodb *mongo.Database,
	scapper *Scapper,
	scannerURL string,
) *api {
	return &api{
		ctx:        ctx,
		userCache:  cache.New(sessionExpiration, time.Minute),
		tokenAuth:  jwtauth.New("HS256", securecookie.GenerateRandomKey(64), nil),
		mongodb:    mongodb,
		scapper:    scapper,
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

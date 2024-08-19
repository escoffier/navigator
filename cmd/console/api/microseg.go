package api

import (
	// "net"
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/security-rd/go-pkg/logging"
)

const keyPrefix = "microseg@"

func (api *api) microSegmentation() http.HandlerFunc {
	// dumb http proxy to microsegmentation service
	remote, err := url.Parse(api.microsegURL)
	if err != nil {
		panic(err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(remote)

	return func(w http.ResponseWriter, r *http.Request) {
		r.Host = remote.Host
		if api.checkBatchCreatingTask(r) {
			reverseProxy.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func (api *api) microseg(r chi.Router) {
	r.Post("/batchpolicies", api.batchCreatePolicies)

	remote, err := url.Parse(api.microsegURL)
	if err != nil {
		panic(err)
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(remote)

	r.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		r.Host = remote.Host
		reverseProxy.ServeHTTP(w, r)
	})
}

func (api *api) batchCreatePolicies(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	remote, err := url.Parse(api.microsegURL)
	if err != nil {
		panic(err)
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(remote)

	r.Header.Set("X-Username", request.GetUsernameFromContext(r.Context()))

	if api.checkBatchCreatingTask(r) {
		reverseProxy.ServeHTTP(w, r)
	} else {
		apperror.RespAndLog(w, ctx, fmt.Errorf("have running task"))
	}
}

func (api *api) checkBatchCreatingTask(r *http.Request) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	// if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/batchpolicies") {
	userName := request.GetUsernameFromContext(r.Context())
	key := keyPrefix + userName
	if _, err := api.redisClient.Get(ctx, key).Result(); err != nil {
		if err == redis.Nil {
			ok, err := api.redisClient.SetNX(ctx, key, "xxxx", time.Second*60).Result()
			if err != nil {
				logging.Get().Err(err).Msgf("set task key %s", key)
				return false
			}

			logging.Get().Err(err).Msgf("get task key %s", key)
			// task has been created by others
			return ok
		}
		return false
	}
	return false
	// }
	// return true
}

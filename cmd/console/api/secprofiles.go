package api

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func (api *api) secProfiles() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute*1)
		defer cancel()
		username := getUsername(ctx)

		r.Header.Set("username", username)

		remote, err := url.Parse(api.secProfileCoreURL)
		if err != nil {
			panic(err)
		}

		reverseProxy := httputil.NewSingleHostReverseProxy(remote)
		reverseProxy.ServeHTTP(w, r)
	}
}

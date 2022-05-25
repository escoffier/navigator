package api

import (
	// "net"
	"net/http"
	"net/http/httputil"
	"net/url"
	// "time"
)

func (api *api) microSegmentation() http.HandlerFunc {
	// dumb http proxy to microsegmentation service
	return func(w http.ResponseWriter, r *http.Request) {

		remote, err := url.Parse(api.microsegURL)
		if err != nil {
			panic(err)
		}

		reverseProxy := httputil.NewSingleHostReverseProxy(remote)
		reverseProxy.ServeHTTP(w, r)
	}
}

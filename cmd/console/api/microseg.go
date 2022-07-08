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
	remote, err := url.Parse(api.microsegURL)
	if err != nil {
		panic(err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(remote)

	return func(w http.ResponseWriter, r *http.Request) {
		reverseProxy.ServeHTTP(w, r)
	}
}

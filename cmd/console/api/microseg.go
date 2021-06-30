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
		// reverseProxy.Transport = &http.Transport{
		// 	Dial: (&net.Dialer{
		// 		Timeout:   15 * time.Second,
		// 		KeepAlive: 15 * time.Second,
		// 	}).Dial,
		// 	ResponseHeaderTimeout: 10 * time.Second,
		// 	ExpectContinueTimeout: 1 * time.Second,
		// }
		reverseProxy.ServeHTTP(w, r)
	}
}

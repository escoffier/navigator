package api

import (
	"context"
	"crypto/tls"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

func (api *api) webhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logging.GetLogger().Info().Msgf("webhook api: %s", r.Host)

		logging.GetLogger().Debug().Msgf("origin url %+v", r.URL)
		if api.webhookURL == nil {
			logging.GetLogger().Warn().Msg("no webhook url!")
			return
		}

		reverseProxy := httputil.NewSingleHostReverseProxy(api.webhookURL)
		reverseProxy.Transport = &http.Transport{
			DialTLSContext: dialTLSContext,
		}
		director := reverseProxy.Director
		reverseProxy.Director = func(req *http.Request) {
			director(req)
			req.Host = req.URL.Host
			var path string
			if strings.Contains(req.URL.Path, "mutating") {
				path = "/mutating"
			} else if strings.Contains(req.URL.Path, "validating") {
				path = "/validating"
			}
			req.URL.Path = path
			logging.GetLogger().Debug().Msgf("target url: %s %+v  %d", req.Method, req.URL, r.ContentLength)
		}
		reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logging.GetLogger().Error().Msgf("proxy handler err %v", err)
			w.WriteHeader(http.StatusBadGateway)
		}

		reverseProxy.ModifyResponse = func(response *http.Response) error {
			logging.GetLogger().Debug().Msgf("response %s", response.Status)
			return nil
		}
		reverseProxy.ServeHTTP(w, r)
	}
}

func dialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	logging.GetLogger().Info().Msgf("dial tls: %s", addr)
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		logging.GetLogger().Error().Msgf("tls hand shake err: %v", err)
		return nil, err
	}

	cs := tlsConn.ConnectionState()
	cert := cs.PeerCertificates[0]

	// Verify here
	err = cert.VerifyHostname(host)
	if err != nil {
		logging.GetLogger().Error().Msgf("VerifyHostname err %v", err)
		return nil, err
	}
	logrus.Info(cert.Subject)
	logging.GetLogger().Debug().Msgf("Subject: %+v", cert.Subject)

	return tlsConn, nil
}

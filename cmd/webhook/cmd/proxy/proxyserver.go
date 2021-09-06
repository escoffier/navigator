package proxy

import (
	"context"
	"crypto/tls"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type Server struct {
	targetUrl      string
	proxy          *httputil.ReverseProxy
	certFile       string
	keyFile        string
	clusterMgrAddr string
}

func NewProxyServer(targetUrl *url.URL, CertFile, KeyFile string) (*Server, error) {
	s := &Server{
		certFile: CertFile,
		keyFile:  KeyFile,
	}

	logrus.Infof("target url: %s", targetUrl.String())

	proxy := httputil.NewSingleHostReverseProxy(targetUrl)

	tlsKeyPair, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	proxy.Transport = &http.Transport{
		DialTLSContext: dialTLSContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates: []tls.Certificate{
				tlsKeyPair,
			},
		},
	}
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = req.URL.Host
	}

	s.proxy = proxy

	return s, nil
}

func (s *Server) Run() error {
	err := http.ListenAndServeTLS(":9443", s.certFile, s.keyFile, s.proxy)
	if err != nil {
		logrus.Errorf("ListenAndServeTLS err: %v", err)
		return err
	}
	return nil
}

func getClusterKey() string {
	wait.Until(func() {
		//ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		//defer cancel()

	}, time.Second, wait.NeverStop)

	return ""
}

func dialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	logrus.Infof("dial tls: %s", addr)
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
		logrus.Errorf("tls hand shake err %v", err)
		return nil, err
	}

	cs := tlsConn.ConnectionState()
	cert := cs.PeerCertificates[0]

	// Verify here
	err = cert.VerifyHostname(host)
	if err != nil {
		logrus.Errorf("VerifyHostname err %v", err)
		return nil, err
	}
	logrus.Info(cert.Subject)

	return tlsConn, nil
}

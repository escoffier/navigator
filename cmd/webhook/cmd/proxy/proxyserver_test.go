package proxy

import (
	"net/url"
	"testing"
)

func TestNewProxyServer(t *testing.T) {
	targetUrl := &url.URL{
		Scheme:   "https",
		RawQuery: "cluster=tensorsec-prod",
		Path:     "/internal/webhook",
		Host:     "console-test-cn.tensorsecurity.cn",
	}
	t.Log(targetUrl.String())
}

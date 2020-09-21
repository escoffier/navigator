// +build !ci

package service

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/facebookarchive/freeport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func setup(t *testing.T,
	f func(w http.ResponseWriter, r *http.Request)) (string, func(t *testing.T)) {
	// disable the log
	logging.Disable()

	// mock ElasticSearch server using httptest
	es := httptest.NewServer(http.HandlerFunc(f))
	esOpts := flag.NewDefaultElasticSearchOpts()
	esOpts.URLs = []string{es.URL}

	port, err := freeport.Get()
	require.NoError(t, err)

	httpOpts := flag.NewDefaultHTTPOpts()
	httpOpts.HTTPListen = fmt.Sprintf(":%d", port)
	httpOpts.HTTPLoggerDisabled = true

	console, err := NewConsole(
		httpOpts, esOpts, flag.NewDefaultEtcdOpts(), flag.NewDefaultMongoOpts(),
		flag.NewDefaultVegetaScannerOpts(), flag.NewDefaultScapOpts())
	require.NoError(t, err)

	stop := console.Run()

	return httpOpts.HTTPListen, func(t *testing.T) {
		stop()
		es.Close()
	}
}

func TestPing(t *testing.T) {
	gateway, teardown := setup(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("{}"))
	})
	defer teardown(t)

	// Testing /ping with a trailing slash here to see if the StripSlashes middleware is effective
	response, err := http.Get(fmt.Sprintf("http://127.0.0.1%s/ping/", gateway))
	require.NoError(t, err)
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	c := string(contents)
	assert.Equal(t, c, "pong")
}

// +build ci

package service

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/facebookarchive/freeport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func setup(t *testing.T) (string, func(t *testing.T)) {
	// disable the log
	logging.Disable()

	port, err := freeport.Get()
	require.NoError(t, err)

	httpOpts := flag.NewDefaultHTTPOpts()
	httpOpts.HTTPListen = fmt.Sprintf(":%d", port)
	httpOpts.HTTPLoggerDisabled = true

	scanner, err := NewScanner(
		httpOpts,
		flag.NewDefaultMongoOpts(),
		flag.NewDefaultClairOpts(),
		flag.NewDefaultRedisOpts(),
		flag.NewDefaultUpdateOpts(),
		flag.NewDefaultHarborOpts(),
	)
	require.NoError(t, err)

	stop := scanner.Run()

	return httpOpts.HTTPListen, func(t *testing.T) {
		stop()
	}
}

func TestPing(t *testing.T) {
	gateway, teardown := setup(t)
	defer teardown(t)

	// Testing /ping with a trailing slash here to see if the StripSlashes middleware is effective
	response, err := http.Get(fmt.Sprintf("http://127.0.0.1%s/ping/", gateway))
	require.NoError(t, err)
	defer util.CloseBodyWithLog(response.Body)

	contents, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	c := string(contents)
	assert.Equal(t, c, "pong")
}

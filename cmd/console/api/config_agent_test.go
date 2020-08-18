// +build !ci

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

func TestConfigAgents(t *testing.T) {
	api, etcdTeardown, mongoTeardown := setupAPI(t, nil, true, true)
	defer func() {
		etcdTeardown()
		mongoTeardown()
	}()

	// create two agent configurations
	var jsonStr = []byte(
		`{"type":"daemonset","name":"test","namespace":"vegeta","etcd":"http://etcd:2379"}`)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, "", bytes.NewBuffer(jsonStr))
		w := httptest.NewRecorder()
		api.createAgent().ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		body, _ := ioutil.ReadAll(w.Body)
		assert.Contains(t, string(body), "agentID")
		assert.Contains(t, string(body), "ObjectID")
	}

	// list agents
	req, _ := http.NewRequest(http.MethodGet, "", nil)
	w := httptest.NewRecorder()
	api.listAgents().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body, _ := ioutil.ReadAll(w.Body)
	assert.NotContains(t, string(body), "yaml")

	// parse the body, and capture one of the agentID and check status
	type response struct {
		Agents []agent `json:"agents"`
	}
	var resp response
	err := json.Unmarshal(body, &resp)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(resp.Agents))

	// Running should be false
	assert.False(t, resp.Agents[0].Running)

	// get agentID
	agentID := resp.Agents[0].ID.Hex()

	// put a heartbeat into the etcd
	api.etcdClient.Put(context.TODO(), fmt.Sprintf("/agents/%s/pods/pod-foobar/heartbeat", agentID),
		`{"start":1575109481,"update":9575109481}`)

	// get agent with agentID, Running should be true
	req, _ = http.NewRequest(http.MethodGet, "", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentID", agentID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w = httptest.NewRecorder()
	api.getAgent().ServeHTTP(w, req)
	body, _ = ioutil.ReadAll(w.Body)
	var agent agent
	err = json.Unmarshal(body, &agent)
	assert.NoError(t, err)
	assert.True(t, agent.Running)
	assert.Equal(t, "test", agent.Name)
	assert.Equal(t, int64(9575109481), agent.LastUpdatedAt)

	// get agent with yaml only
	req, _ = http.NewRequest(http.MethodGet, "", nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("agentID", agentID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	q := req.URL.Query()
	q.Add("yaml", "1")
	req.URL.RawQuery = q.Encode()

	w = httptest.NewRecorder()
	api.getAgent().ServeHTTP(w, req)
	body, _ = ioutil.ReadAll(w.Body)
	assert.Equal(t, string(body), "Test")

	// testing the deleteAgent api
	req, _ = http.NewRequest(http.MethodDelete, "", nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("agentID", agentID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w = httptest.NewRecorder()
	api.deleteAgent().ServeHTTP(w, req)
	body, _ = ioutil.ReadAll(w.Body)
	assert.Equal(t, string(body), `{"status":"ok"}`)

	// list agents again
	req, _ = http.NewRequest(http.MethodGet, "", nil)
	w = httptest.NewRecorder()
	api.listAgents().ServeHTTP(w, req)
	body, _ = ioutil.ReadAll(w.Body)

	var resp1 response
	err = json.Unmarshal(body, &resp1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(resp1.Agents))
}

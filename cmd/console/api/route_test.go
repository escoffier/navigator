// +build !ci

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T) *httptest.Server {
	r := chi.NewRouter()
	SetupRoutes(context.TODO(), r, 500*time.Millisecond, nil, nil, "", nil, nil)
	return httptest.NewServer(r)
}

func TestAPIUnauthenticated(t *testing.T) {
	ts := setupTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/auth/user", nil)
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLoginError(t *testing.T) {
	ts := setupTestServer(t)
	req, _ := http.NewRequest(
		"POST",
		ts.URL+"/api/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"wrong"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLoginAndExpired(t *testing.T) {
	ts := setupTestServer(t)
	req, _ := http.NewRequest(
		"POST",
		ts.URL+"/api/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"admin"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "jwt", resp.Cookies()[0].Name)

	jwtToken := resp.Cookies()[0].Value

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/auth/user", nil)
	req.Header.Set("Authorization", fmt.Sprintf("BEARER %s", jwtToken))
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(750 * time.Millisecond)
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/auth/user", nil)
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogout(t *testing.T) {
	ts := setupTestServer(t)
	req, _ := http.NewRequest(
		"POST",
		ts.URL+"/api/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"admin"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "jwt", resp.Cookies()[0].Name)

	jwtToken := resp.Cookies()[0].Value

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", fmt.Sprintf("BEARER %s", jwtToken))
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/auth/user", nil)
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// +build !ci

package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIUnauthenticated(t *testing.T) {
	ts := setupTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/rest-auth/user", nil)
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLoginError(t *testing.T) {
	ts := setupTestServer(t)
	req, _ := http.NewRequest(
		"POST",
		ts.URL+"/api/v1/rest-auth/login",
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
		ts.URL+"/api/v1/rest-auth/login",
		strings.NewReader(`{"username":"admin","password":"admin"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "jwt", resp.Cookies()[0].Name)

	jwtToken := resp.Cookies()[0].Value

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/rest-auth/user", nil)
	req.Header.Set("Authorization", fmt.Sprintf("BEARER %s", jwtToken))
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(750 * time.Millisecond)
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/rest-auth/user", nil)
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogout(t *testing.T) {
	ts := setupTestServer(t)
	req, _ := http.NewRequest(
		"POST",
		ts.URL+"/api/v1/rest-auth/login",
		strings.NewReader(`{"username":"admin","password":"admin"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "jwt", resp.Cookies()[0].Name)

	jwtToken := resp.Cookies()[0].Value

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/rest-auth/logout", nil)
	req.Header.Set("Authorization", fmt.Sprintf("BEARER %s", jwtToken))
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/rest-auth/user", nil)
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

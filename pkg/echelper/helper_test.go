package echelper

import (
	"context"
	"net/http"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestRiskStats(t *testing.T) {
	// mock http
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterRegexpResponder(http.MethodGet, regexp.MustCompile(".*/api/v1/palace/internal/risk/stats.*"),
		httpmock.NewStringResponder(200, `{
    "code": 0,
    "message": "success",
    "data": {
        "fake1": [
            {
                "enKey": "ATT&CK",
                "zhKey": "ATT&CK",
                "count": 561,
                "severity": 4
            },
            {
                "enKey": "kubeMonitor",
                "zhKey": "集群风险监控",
                "count": 28,
                "severity": 2
            }
        ],
        "fake2": [
            {
                "enKey": "kubeMonitor",
                "zhKey": "集群风险监控",
                "count": 28,
                "severity": 2
            }
        ]
    }
}`))

	sherlockClient := NewSherlockClient("fake")
	res, err := sherlockClient.RiskStats(context.Background(), "fake")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, 2, len(res["fake1"]))
	assert.Equal(t, "ATT&CK", res["fake1"][0].EnKey)
	assert.Equal(t, "kubeMonitor", res["fake2"][0].EnKey)
}

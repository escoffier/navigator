package clusterManager

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
)

func Test_clusterManager_postClusterInfo(t *testing.T) {
	type fields struct {
		masterAddr    string
		CusterID      string
		Name          string
		Token         string
		CaData        string
		apiServerAddr string
		description   string
		httpClient    *http.Client
		client        kubernetes.Interface
		nodeInformer  v1.NodeInformer
		resyncPeriod  time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClusterManager{
				masterAddr:    tt.fields.masterAddr,
				CusterID:      tt.fields.CusterID,
				Name:          tt.fields.Name,
				Token:         tt.fields.Token,
				CaData:        tt.fields.CaData,
				apiServerAddr: tt.fields.apiServerAddr,
				description:   tt.fields.description,
				httpClient:    tt.fields.httpClient,
				client:        tt.fields.client,
				nodeInformer:  tt.fields.nodeInformer,
				resyncPeriod:  tt.fields.resyncPeriod,
			}
			if err := c.registerClusterInfo(); (err != nil) != tt.wantErr {
				t.Errorf("registerClusterInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_clusterManager_postClusterInfo1(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	type fields struct {
		masterAddr    string
		CusterID      string
		Name          string
		Token         string
		CaData        string
		apiServerAddr string
		description   string
		httpClient    *http.Client
		tlsClient     bool
		client        kubernetes.Interface
		nodeInformer  v1.NodeInformer
		resyncPeriod  time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test-key",
			fields: fields{
				masterAddr:    "https://console-test-cn.tensorsecurity.cn",
				CusterID:      "123456",
				Name:          "fake cluster",
				Token:         "123456",
				CaData:        "333333333",
				apiServerAddr: "192.168.254.123",
				description:   "fake cluster",
				httpClient: &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				},
				tlsClient:    false,
				client:       nil,
				nodeInformer: nil,
				resyncPeriod: 0,
			},
		},
		{
			name: "test-key-1",
			fields: fields{
				masterAddr:    "https://console-test-cn.tensorsecurity.cn",
				CusterID:      "123456",
				Name:          "fake cluster",
				Token:         "123456",
				CaData:        "333333333",
				apiServerAddr: "192.168.254.123",
				description:   "fake cluster",
				httpClient:    http.DefaultClient,
				tlsClient:     false,
				client:        nil,
				nodeInformer:  nil,
				resyncPeriod:  0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClusterManager{
				masterAddr:    tt.fields.masterAddr,
				CusterID:      tt.fields.CusterID,
				Name:          tt.fields.Name,
				Token:         tt.fields.Token,
				CaData:        tt.fields.CaData,
				apiServerAddr: tt.fields.apiServerAddr,
				description:   tt.fields.description,
				httpClient:    tt.fields.httpClient,
				tlsClient:     tt.fields.tlsClient,
				client:        tt.fields.client,
				nodeInformer:  tt.fields.nodeInformer,
				resyncPeriod:  tt.fields.resyncPeriod,
			}
			if err := c.registerClusterInfo(); (err != nil) != tt.wantErr {
				t.Errorf("registerClusterInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

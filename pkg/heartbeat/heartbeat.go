package heartbeat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.etcd.io/etcd/clientv3"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	agentTimeoutSecs  = 15
	heartbeatInterval = 10 * time.Second
)

// Heartbeat defines the struct for our agent heartbeats
type Heartbeat struct {
	Start  int64 `json:"start"`
	Update int64 `json:"update"`
}

// Update updates the heartbeat
// Run this in a Go routine
func Update(ctx context.Context, etcdClient *clientv3.Client, key string) {
	hb := &Heartbeat{
		Start:  time.Now().Unix(),
		Update: time.Now().Unix(),
	}
	update(ctx, etcdClient, key, hb)
loop:
	for {
		select {
		case <-time.After(heartbeatInterval):
			update(ctx, etcdClient, key, hb)
		case <-ctx.Done():
			break loop
		}
	}
}

func update(ctx context.Context, etcdClient *clientv3.Client, key string, hb *Heartbeat) {
	// send etcd the heartbeat
	newCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	hb.Update = time.Now().Unix()
	hbBytes, err := json.Marshal(hb)
	if err != nil {
		panic(err)
	}

	_, err = etcdClient.Put(newCtx, key, string(hbBytes))
	if err != nil {
		logging.GetLogger().Error().
			Err(err).
			Msg("error in sending heartbeat to etcd")
	}
}

// GetAll is to get the agent heartbeats from etcd by Agent ID
// also check if we have one pod/container is active
// this can be improved without O(n^2) here
func GetAll(
	ctx context.Context,
	etcdClient *clientv3.Client,
	agentID string,
) (map[string]Heartbeat, int64, bool, error) {
	heartbeats := make(map[string]Heartbeat)
	running := false
	var lastUpdatedAt int64

	key := fmt.Sprintf("/agents/%s/pods/", agentID)
	etcdResp, err := etcdClient.Get(ctx, key, clientv3.WithPrefix())
	if err != nil {
		return heartbeats, lastUpdatedAt, running, err
	}

	for _, kv := range etcdResp.Kvs {
		kvkey := string(kv.Key)
		podname := strings.ReplaceAll(
			kvkey[strings.Index(kvkey, "/pods")+6:], "/heartbeat", "")

		// Unmarshall the heartbeat json string
		var hb Heartbeat
		err = json.Unmarshal(kv.Value, &hb)
		if err != nil {
			return heartbeats, lastUpdatedAt, running, err
		}

		// if any heartbeat.Update > now - 15s, set Running to true
		if hb.Update > time.Now().Unix()-agentTimeoutSecs {
			running = true
		}

		// find the biggest heartbeat's update and make it lastUpdatedAt
		if hb.Update > lastUpdatedAt {
			lastUpdatedAt = hb.Update
		}

		heartbeats[podname] = hb
	}
	return heartbeats, lastUpdatedAt, running, nil
}

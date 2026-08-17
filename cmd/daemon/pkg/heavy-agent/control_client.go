package heavyagent

import (
	"context"
	"sync"

	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

// ControlClient wraps the generated NetPolicyControlClient with the
// connectivity-state-based resync-callback mechanism that replaces
// Client's TCP-reconnect-triggered ReConnectCB.
type ControlClient struct {
	pb.NetPolicyControlClient

	conn *grpc.ClientConn

	mu  sync.Mutex
	cbs []ReConnectCB
}

func NewControlClient(address string) (*ControlClient, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	c := &ControlClient{
		NetPolicyControlClient: pb.NewNetPolicyControlClient(conn),
		conn:                   conn,
	}
	go c.watchConnectivity()
	return c, nil
}

// AddReConnectionCallback registers cb to run whenever the underlying
// connection transitions from TRANSIENT_FAILURE back to READY -- the
// gRPC-native signal for "the peer was unreachable and is now back,"
// replacing the TCP client's reconnect-on-EOF trigger.
func (c *ControlClient) AddReConnectionCallback(cb ReConnectCB) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cbs = append(c.cbs, cb)
}

// shouldFireResync reports whether a connectivity transition from old to
// new should trigger the registered resync callbacks.
func shouldFireResync(old, new connectivity.State) bool {
	return old == connectivity.TransientFailure && new == connectivity.Ready
}

func (c *ControlClient) watchConnectivity() {
	state := c.conn.GetState()
	for {
		if !c.conn.WaitForStateChange(context.Background(), state) {
			return
		}
		newState := c.conn.GetState()
		if shouldFireResync(state, newState) {
			c.mu.Lock()
			cbs := append([]ReConnectCB(nil), c.cbs...)
			c.mu.Unlock()
			for _, cb := range cbs {
				if err := cb(); err != nil {
					logging.Get().Err(err).Msg("control-plane resync callback failed")
				}
			}
		}
		state = newState
	}
}

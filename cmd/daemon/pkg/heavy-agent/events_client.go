package heavyagent

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

const eventsRetryBackoff = 500 * time.Millisecond

// EventsClient streams PolicyMatchEvents from NetPolicyEvents, replacing
// the length-prefixed framing/dispatch loop in event.go's EventProcessor.
type EventsClient struct {
	client pb.NetPolicyEventsClient
	conn   *grpc.ClientConn
}

func NewEventsClient(address string) (*EventsClient, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &EventsClient{
		client: pb.NewNetPolicyEventsClient(conn),
		conn:   conn,
	}, nil
}

// Run subscribes to policy-match events and calls onEvent for each one
// received, re-subscribing with a short backoff whenever the stream ends
// (including on error). It returns when ctx is cancelled.
func (c *EventsClient) Run(ctx context.Context, onEvent func(*pb.PolicyMatchEvent)) {
	for {
		if ctx.Err() != nil {
			return
		}
		stream, err := c.client.SubscribeEvents(ctx, &pb.SubscribeEventsRequest{ClientId: "daemon"})
		if err != nil {
			logging.Get().Err(err).Msg("subscribe to policy events")
			time.Sleep(eventsRetryBackoff)
			continue
		}
		for {
			evt, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Get().Err(err).Msg("receive policy event")
				time.Sleep(eventsRetryBackoff)
				break
			}
			if match := evt.GetPolicyMatch(); match != nil {
				onEvent(match)
			}
		}
	}
}

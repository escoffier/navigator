package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/avast/retry-go"
	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const postUrlPath = "/internal/attack/logs"

type WafgHandler struct {
	httpClient *http.Client
	postUrl    string
}

// Handle implements heavyagent.Handler.
func (wh *WafgHandler) Handle(ctx context.Context, obj interface{}) error {
	log.Info().Msg("process waf event")
	event, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	err = wh.sendMessage(ctx, event)
	if err != nil {
		log.Err(err).Msg("post microseg event err")
	}
	return nil
}

func (wh *WafgHandler) sendMessage(ctx context.Context, message []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.postUrl, bytes.NewReader(message))
	if err != nil {
		return err
	}

	respHandler := func(resp *http.Response, err error) error {
		if err != nil {
			log.Err(err).Msgf("post cluster info err : %v", err)
			return err
		}
		if resp.StatusCode != http.StatusOK {
			log.Error().Msgf("http resp error: %s", resp.Status)
			return fmt.Errorf("http resp error: %s", resp.Status)
		}
		return nil
	}

	return util.HTTPRequest(ctx, wh.httpClient, request, respHandler, retry.Attempts(3))
}

func NewHandler(clusterManagerSvc string) heavyagent.Handler {
	return &WafgHandler{
		httpClient: http.DefaultClient,
		postUrl:    clusterManagerSvc + postUrlPath,
	}
}

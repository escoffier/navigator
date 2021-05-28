package util

import (
	"context"
	"fmt"
	"net/http"

	"github.com/avast/retry-go"
)

type ResponseHandleFunc func(resp *http.Response, err error) error

func HTTPRequest(ctx context.Context, httpCli *http.Client, req *http.Request, respHandle ResponseHandleFunc, retryOpts ...retry.Option) (err error) {
	var resp *http.Response
	err = RetryWithBackoff(ctx, func() error {
		var err error
		resp, err = httpCli.Do(req.WithContext(ctx))
		if err == nil {
			if resp.StatusCode != http.StatusOK && resp.StatusCode >= 500 {
				return fmt.Errorf("status code is %d", resp.StatusCode)
			}
			return nil
		}
		return err

	}, retryOpts...)

	if err != nil {
		return respHandle(resp, err)
	}
	defer CloseBodyWithLog(resp.Body)

	return respHandle(resp, err)
}

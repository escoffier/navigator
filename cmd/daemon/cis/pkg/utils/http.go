package utils

import (
	"context"
	"io"
	"net/http"
)

func HTTPRequest(ctx context.Context, method, api string, headers map[string]string, payload io.Reader) (
	statusCode int, data []byte, err error) {
	var (
		req      *http.Request
		response *http.Response
	)

	req, err = http.NewRequestWithContext(ctx, method, api, payload)
	if err != nil {
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	client := &http.Client{}
	if response, err = client.Do(req); err == nil {
		defer response.Body.Close()
		statusCode = response.StatusCode
		data, err = io.ReadAll(response.Body)
	}

	return
}

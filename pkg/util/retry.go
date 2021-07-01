package util

import (
	"context"
	"time"

	"github.com/avast/retry-go"
)

var (
	defaultRetryOptions = []retry.Option{
		retry.MaxDelay(1 * time.Second),
		retry.MaxJitter(200 * time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(false),
	}
)

type RetryFunc func() error

var DefaultRetryConf = &RetryConf{
	retryDelay:    time.Millisecond * 200,
	maxRetryDelay: time.Millisecond * 2000,
	maxRetryCount: 10,
}

type RetryConf struct {
	retryDelay    time.Duration
	maxRetryDelay time.Duration
	maxRetryCount int
}

func WithRetry(f RetryFunc, conf *RetryConf) error {
	retryDelay := conf.retryDelay
	retryCount := 0
	for {
		err := f()
		if err == nil {
			return nil
		}

		if retryCount > conf.maxRetryCount {
			return err
		}

		time.Sleep(retryDelay)
		retryCount++
		retryDelay *= 2
		if retryDelay > conf.maxRetryDelay {
			retryDelay = conf.maxRetryDelay
		}
	}
}

// RetryWithBackoff uses Backoff algo to retry using default settings, extraOpts will override existing options.
func RetryWithBackoff(ctx context.Context, f retry.RetryableFunc, extraOpts ...retry.Option) error {
	retryOpts := make([]retry.Option, 0, 5)
	retryOpts = append(retryOpts, retry.Context(ctx))
	retryOpts = append(retryOpts, defaultRetryOptions...)
	retryOpts = append(retryOpts, extraOpts...)

	return retry.Do(f, retryOpts...)
}

package util

import "time"

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

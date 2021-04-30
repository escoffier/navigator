package util

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestRetry(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	var counter int
	testFunc := func() error {
		if rand.Uint32()%100 == 0 {
			return nil
		}

		counter++
		t.Log("random error", counter)
		return fmt.Errorf("test error")
	}

	err := WithRetry(testFunc, DefaultRetryConf)
	t.Log(err)
}

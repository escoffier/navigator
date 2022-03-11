package util

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestLimiter_AllowKey(t *testing.T) {
	var (
		testKey1 = "fake1"
		testKey2 = "fake2"
	)
	lmt := NewLimiter(rate.Every(time.Second), 1)

	// testKey1
	if !lmt.AllowKey(testKey1) {
		t.Fatal("testKey1: first time count should allow")
	}

	// testKey1
	if lmt.AllowKey(testKey1) {
		t.Fatal("testKey1: second time count should not allow because it exceeds 1 request per second")
	}

	// testKey2
	if !lmt.AllowKey(testKey2) {
		t.Fatal("testKey2: first time count should allow")
	}

	time.Sleep(time.Second)

	// testKey1
	if !lmt.AllowKey(testKey1) {
		t.Fatal("testKey1: third time count should allow because the 1 second window has passed")
	}

	// testKey2
	if !lmt.AllowKey(testKey2) {
		t.Fatal("testKey2: second time count should allow because the 1 second window has passed")
	}
}

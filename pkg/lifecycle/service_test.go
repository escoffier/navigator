package lifecycle

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testService struct {
	Service
	started          bool
	goRoutineStopped bool
	cleanup          bool
}

func (ts *testService) Run() func() {
	ts.started = true
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		<-done
		ts.goRoutineStopped = true
		close(stopped)
	}()
	return func() {
		close(done)
		<-stopped
		ts.cleanup = true
	}
}

func TestSimpleEarlyStop(t *testing.T) {
	ts := &testService{}
	app := NewApplication(ts)
	go app.Run()
	app.Stop()
	assert.True(t, ts.started)
	assert.True(t, ts.goRoutineStopped)
	assert.True(t, ts.cleanup)
}

func TestStopAfter(t *testing.T) {
	ts := &testService{}
	app := NewApplication(ts)
	go app.Run()
	<-time.After(100 * time.Millisecond)
	app.Stop()
}

func TestPanic(t *testing.T) {
	ts := &testService{}
	app := NewApplication(ts)
	go app.Run()
	<-time.After(100 * time.Millisecond)
	assert.Panics(t, func() {
		app.Run()
	})
}

func TestTwoServices(t *testing.T) {
	ts1 := &testService{}
	app1 := NewApplication(ts1)
	go app1.Run()
	ts2 := &testService{}
	app2 := NewApplication(ts2)
	go app2.Run()

	app1.Stop()
	app2.Stop()
}

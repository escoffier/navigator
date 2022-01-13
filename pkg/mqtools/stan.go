package mqtools

import (
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ConnFunc func() (stan.Conn, error)

/* StanConn is a wrapper to support automatically retry to connect to stan in certain circumstances */
type StanConn struct {
	connVal    atomic.Value
	f          ConnFunc
	connSignal chan struct{}
}

func NewStanConn(f ConnFunc) *StanConn {
	c := &StanConn{
		connVal:    atomic.Value{},
		f:          f,
		connSignal: make(chan struct{}, 1),
	}
	conn, err := c.f()
	if err == nil {
		c.setConn(conn)
		c.connSignal <- struct{}{}
		close(c.connSignal)
	} else {
		logging.GetLogger().Err(err).Msg("error get connection to stan")
	}

	c.asyncLoop()
	return c
}
func (c *StanConn) Notif() <-chan struct{} {
	return c.connSignal
}
func (c *StanConn) Connected() bool {
	return c.connVal.Load() != nil
}
func (c *StanConn) setConn(conn stan.Conn) {
	c.connVal.Store(conn)
}
func (c *StanConn) Conn() (stan.Conn, bool) {
	o := c.connVal.Load()
	if o == nil {
		return nil, false
	}
	return o.(stan.Conn), true
}

func (c *StanConn) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("panic %v. stack: %s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			tryReconn := false
			first := false
			if c.Connected() { // check connection
				conn, ok := c.Conn()
				if !ok {
					tryReconn = true
				} else if conn.NatsConn() == nil || !conn.NatsConn().IsConnected() {
					logging.GetLogger().Warn().Msg("Stan Nats connection not connected")
					tryReconn = true
				}
			} else {
				first = true
				tryReconn = true
			}
			if tryReconn {
				logging.GetLogger().Info().Msg("try to reconnect stan")

				conn, err := c.f()
				if err == nil {
					c.setConn(conn)
					if first {
						c.connSignal <- struct{}{}
						close(c.connSignal)
					}

				} else {
					logging.GetLogger().Err(err).Msg("error get connection to stan")
				}
			}

		}
	}()
}

package mongotools

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	newDBTimeout = 1 * time.Second
)

type ClientWrapper struct {
	cliVal    atomic.Value
	checkIntv time.Duration

	opts   *options.ClientOptions
	stopCh chan struct{}

	dbMap *sync.Map

	dbMutex sync.RWMutex
}

type DatabaseWrapper struct {
	cliWrapper   *ClientWrapper
	databaseName string
}

func NewMongoClient(opt *options.ClientOptions, checkIntv time.Duration) (*ClientWrapper, error) {
	client, err := newClientWithTimeout(opt)
	if err != nil {
		return nil, err
	}

	wrapper := &ClientWrapper{
		checkIntv: checkIntv,
		opts:      opt,
		dbMap:     new(sync.Map),
		stopCh:    make(chan struct{}, 1),
	}
	wrapper.cliVal.Store(client)
	return wrapper, nil
}

func (w *DatabaseWrapper) Get() *mongo.Database {
	db, _ := w.cliWrapper.getDB(w.databaseName)
	return db
}

func (w *ClientWrapper) getDB(dbName string) (*mongo.Database, bool) {
	db, exist := w.dbMap.Load(dbName)
	return db.(*mongo.Database), exist
}
func (w *ClientWrapper) Database(databaseName string, opts ...*options.DatabaseOptions) *DatabaseWrapper {
	cli, _ := w.Client()
	w.dbMutex.Lock()
	defer w.dbMutex.Unlock()
	w.setDatabase(cli, databaseName, opts...)
	return &DatabaseWrapper{
		cliWrapper:   w,
		databaseName: databaseName,
	}
}

func (w *ClientWrapper) setDatabase(cli *mongo.Client, databaseName string, opts ...*options.DatabaseOptions) {
	db := cli.Database(databaseName, opts...)

	w.dbMap.Store(databaseName, db)
}
func (w *ClientWrapper) setClient(cli *mongo.Client) {
	w.cliVal.Store(cli)
}

func (w *ClientWrapper) Client() (*mongo.Client, bool) {
	v := w.cliVal.Load()
	return v.(*mongo.Client), v != nil
}

func (w *ClientWrapper) Connect(ctx context.Context) error {
	cli, _ := w.Client()
	err := cli.Connect(ctx)
	if err != nil {
		return err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic when monitoring mongo client connection: %v. Stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(w.checkIntv)
		defer ticker.Stop()
		toStop := false
		for !toStop {
			select {
			case <-ticker.C:
				w.checkAndReconnect(ctx)
			case <-w.stopCh:
				toStop = true
				break
			}
		}
	}()
	return nil
}

type res struct {
	db  *mongo.Client
	err error
}

func newClientWithTimeout(opts *options.ClientOptions) (*mongo.Client, error) {
	resChan := make(chan res, 1)
	timer := time.NewTimer(newDBTimeout)
	defer timer.Stop()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic when newClient: %v. Stack: %s", r, debug.Stack())
			}
		}()
		defer close(resChan)

		db, err := mongo.NewClient(opts)
		resChan <- res{
			db:  db,
			err: err,
		}
	}()

	select {
	case r := <-resChan:
		return r.db, r.err
	case <-timer.C:
		return nil, errors.New("timeout")
	}
}

func (w *ClientWrapper) checkAndReconnect(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when checking connection alive: %v. Stack: %s", r, debug.Stack())
		}
	}()

	cli, _ := w.Client()
	failNum := 0
	toStop := false
	for i := 0; i < 3 && !toStop; i++ {
		func() {
			mongoCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			err := cli.Ping(mongoCtx, readpref.Primary())
			if err != nil {
				logging.GetLogger().Warn().Msgf("Ping error (%d time): %v", i+1, err)
				failNum++
				if failNum < 3 {
					time.Sleep(200 * time.Millisecond)
				}
			} else {
				if failNum > 0 {
					logging.GetLogger().WithContext(mongoCtx).Infof("Ping successes after failure")
				}
				toStop = true
				return
			}
		}()
	}
	if failNum == 3 {
		logging.GetLogger().Error().Msgf("Ping failed 3 times, try to reinitialize")

		newCli, err := newClientWithTimeout(w.opts)
		if err != nil {
			logging.GetLogger().Error().Msgf("new client error when auto retry: %v", err)
		} else {

			mongoCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			connErr := newCli.Connect(mongoCtx)
			if connErr != nil {
				logging.GetLogger().Error().Msgf("new client conn error when auto retry: %v", err)
			} else {
				keys := make([]string, 0, 2)
				w.dbMutex.RLock()
				w.dbMap.Range(func(dbName interface{}, db interface{}) bool {
					keys = append(keys, dbName.(string))
					return true
				})
				for _, key := range keys {
					w.setDatabase(newCli, key)
				}
				w.setClient(newCli)
				w.dbMutex.RUnlock()
				logging.GetLogger().Info().Msgf("Reset the mongo client done when error connected")

				mongoCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := cli.Disconnect(mongoCtx)
				if err != nil {
					logging.GetLogger().Error().Msgf("disconnect mongo error: %v", err)
				} else {
					logging.GetLogger().Info().Msg("Disconnected from the old")
				}
				return
			}
		}
	}
}

func (w *ClientWrapper) Disconnect(ctx context.Context) error {
	w.stopCh <- struct{}{}

	cli, _ := w.Client()
	return cli.Disconnect(ctx)
}

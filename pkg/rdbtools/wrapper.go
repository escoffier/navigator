package rdbtools

import (
	"context"
	"errors"
	"runtime/debug"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gorm.io/gorm"
)

const (
	newDBTimeout = 1 * time.Second
)

type GormWrapper struct {
	dbVal     atomic.Value
	checkIntv time.Duration

	stopCh chan struct{}
	new    func() (*gorm.DB, error)
}

func GormWrapperOpen(checkIntv time.Duration, newDB func() (*gorm.DB, error)) (*GormWrapper, error) {
	db, err := newDBWithTimeout(newDB)
	if err != nil {
		return nil, err
	}
	gw := &GormWrapper{
		stopCh:    make(chan struct{}, 1),
		new:       newDB,
		checkIntv: checkIntv,
	}
	gw.setDB(db)
	gw.asyncLoop()

	return gw, nil
}

type res struct {
	db  *gorm.DB
	err error
}

func newDBWithTimeout(newDB func() (*gorm.DB, error)) (db *gorm.DB, err error) {
	resChan := make(chan res, 1)
	timer := time.NewTimer(newDBTimeout)

	defer timer.Stop()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic when newDB: %v. Stack: %s", r, debug.Stack())
			}
		}()
		defer close(resChan)

		db, err := newDB()
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

func (gw *GormWrapper) setDB(db *gorm.DB) {
	gw.dbVal.Store(db)
}
func (gw *GormWrapper) Get() *gorm.DB {
	v := gw.dbVal.Load()
	return v.(*gorm.DB)
}

func (gw *GormWrapper) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic when monitoring gorm client connection: %v. Stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(gw.checkIntv)
		defer ticker.Stop()
		toStop := false
		for !toStop {
			select {
			case <-ticker.C:
				gw.checkAndReconnect()
			case <-gw.stopCh:
				toStop = true
				break
			}
		}
	}()
}
func (gw *GormWrapper) Close() error {
	gw.stopCh <- struct{}{}

	pgCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	db := gw.Get()
	sqlDB, err := db.WithContext(pgCtx).DB()
	if err != nil {
		logging.GetLogger().Warn().Msgf("db error: %s", err)
		return err
	} else {
		clsErr := sqlDB.Close()
		if clsErr != nil {
			logging.GetLogger().Err(clsErr).Msg("close database error")
			return clsErr
		}
	}

	return nil
}
func (gw *GormWrapper) checkAndReconnect() error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when checking connection alive: %v. Stack: %s", r, debug.Stack())
		}
	}()

	db := gw.Get()
	failNum := 0
	toStop := false
	for i := 0; i < 3 && !toStop; i++ {
		func() {
			pgCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			sqlDB, err := db.WithContext(pgCtx).DB()
			if err != nil {
				logging.GetLogger().Warn().Msgf("[%d time] ping error: %s", i+1, err)
				failNum++
				if failNum < 3 {
					time.Sleep(200 * time.Millisecond)
				}
				return
			}
			pingErr := sqlDB.PingContext(pgCtx)
			if pingErr != nil {
				logging.GetLogger().Warn().Msgf("[%d time] ping error: %s", i+1, pingErr)
				failNum++
				if failNum < 3 {
					time.Sleep(200 * time.Millisecond)
				}
				return
			}
			if failNum > 0 {
				logging.GetLogger().WithContext(pgCtx).Infof("Ping successes after failure")
			}
			toStop = true
		}()
	}

	if failNum == 3 {
		logging.GetLogger().Error().Msgf("Ping failed 3 times, try to reinitialize")

		newDB, err := newDBWithTimeout(gw.new)
		if err != nil {
			logging.GetLogger().Err(err).Msg("wrapper reconn: new db error")
		} else {
			gw.setDB(newDB)
			logging.GetLogger().Info().Msg("wrapper reconn: Setted new db")

			pgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			sqlDB, err := db.WithContext(pgCtx).DB()
			if err != nil {
				logging.GetLogger().Warn().Msgf("wrapper reconn: ping error: %s", err)
			} else {
				clsErr := sqlDB.Close()
				if clsErr != nil {
					logging.GetLogger().Err(clsErr).Msg("wrapper reconn: close database error")
				} else {
					logging.GetLogger().Info().Msg("wrapper reconn: old db closed")
				}
			}
		}
	}
	return nil
}

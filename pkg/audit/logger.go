package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"
	"strings"
	"sync"
)

var fsOnce sync.Once
var fsStore1 Store
var fsQueue *util.Queue

type fsStore struct {
	Logger zerolog.Logger
}

func newFsStore(logger zerolog.Logger) Store {
	return &fsStore{Logger: logger}
}

func (s *fsStore) store(ctx context.Context, auditEvt *model.NaviAuditEvent) error {
	jsonData, err := json.Marshal(auditEvt)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("Response: %d %s", http.StatusOK, statusLabel(http.StatusOK))
	s.Logger.WithLevel(zerolog.InfoLevel).RawJSON("event", jsonData).Msg(msg)
	return nil
}

func FsAudit() func(next http.Handler) http.Handler {
	fsOnce.Do(func() {
		logger := log.With().Str("service", strings.ToLower("console"))
		fsStore1 = newFsStore(logger.Logger())
		fsQueue = util.NewQueue()
		go sendLog(fsStore1, fsQueue)
	})

	return RequestLogger(fsStore1, fsQueue)
}

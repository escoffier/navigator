package audit

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	//"gitlab.com/security-rd/go-pkg/elastic"
	v7 "github.com/olivere/elastic/v7"
	"net/http"
	"time"
)

const maxQueueLen = 1024

type ESStore struct {
	es *v7.Client
}

func newESStore(client *v7.Client) Store {
	return &ESStore{es: client}
}

func (s *ESStore) store(ctx context.Context, auditEvt *model.NaviAuditEvent) error {
	index := fmt.Sprintf("%s%s", "navi-audit-", time.Now().Format("2006-01-02"))
	_, err := s.es.Index().Index(index).Id(auditEvt.RequestID).BodyJson(auditEvt).Do(ctx)
	return err
}

func ESAudit(client *v7.Client) func(next http.Handler) http.Handler {
	store := newESStore(client)
	queue := util.NewQueue()

	go sendLog(store, queue)

	return RequestLogger(store, queue)
}

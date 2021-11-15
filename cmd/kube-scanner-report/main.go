package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/go-chi/chi"

	"gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report/env"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	stopCh      = make(chan struct{})
	stopOnce    sync.Once
	maxTaskTime = time.Duration(util.GetIntValWithDefault(env.MaxTaskTimeSec, env.DefaultMaxTaskTimeSec)) * time.Second
	uuid        = util.GetEnvWithDefault(env.UUID, "")
)

func main() {
	if maxTaskTime == 0 || uuid == "" {
		log.Fatalf("invalid arg, MaxTaskTimeSec:%s, uuid:%s", maxTaskTime, uuid)
	}

	r := chi.NewRouter()
	r.Post("/", handler)
	srv := http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	closed := make(chan struct{})

	go func() {
		<-time.After(maxTaskTime)
		log.Printf("timeout, maxTaskTime:%s", maxTaskTime)
		stopOnce.Do(func() {
			close(stopCh)
		})
	}()

	go func() {
		<-stopCh
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server Shutdown: %v\n", err)
		}
		close(closed)
	}()

	log.Printf("ready to start http server ...\n")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("HTTP server ListenAndServe: %v\n", err)
	}

	<-closed
	log.Print("exit 0\n")
}

const (
	timeout = time.Minute * 5
	authKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	defer func() {
		stopOnce.Do(func() {
			close(stopCh)
		})
	}()

	log.Printf("receive request...\n")

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	u, err := generateURL(uuid)
	if err != nil {
		log.Printf("invalid url")
		apperror.RespAndLog(w, ctx, err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, r.Body)
	if err != nil {
		apperror.RespAndLog(w, ctx, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tensorsec-cicd-key", authKey)
	rsp, err := client.Do(req)
	if err != nil {
		log.Printf("send report fail, err:%s\n", err)
	} else {
		defer rsp.Body.Close()
		log.Printf("response status code:%d", rsp.StatusCode)
	}

	log.Printf("forward to console...\n")
	response.Ok(w)
}

func generateURL(uuid string) (string, error) {
	u, err := url.Parse(util.GetEnvWithDefault(env.ReportURL, env.DefaultReportURL))
	if err != nil {
		return "", err
	}

	u.Path = path.Join(u.Path, uuid)

	return u.String(), nil
}

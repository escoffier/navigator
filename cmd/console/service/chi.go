package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	redis "github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
)

var (
	jwtSignKey = []byte("skielsJKL@qlLKYY9091LSAqweVGY8769VHKskafhw239s$kskSJ)ksj!jHN7hJs")
)

func setupChiRouter(
	ctx context.Context,
	rdb *databases.RDBInstance,
	es *elastic.ESClient,
	scannerURL string,
	secProfilesCoreURL string,
	microsegURL string,
	webhookURL string,
	httpLoggerDisabled bool,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	ecCli pb.EventsCenterBizServiceClient,
) http.Handler {
	// ch := make(chan model.AccessLog, 1000)
	tokenAuth := jwtauth.New("HS256", jwtSignKey, nil)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Compress(5))
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(lang.AcceptLanguageMiddleware)
	// r.Use(AccessMiddlewares(ch))
	if !httpLoggerDisabled {
		r.Use(middleware.Logger)
	}

	api.SetupRoutes(ctx, r,
		tokenAuth,
		rdb,
		scannerURL,
		secProfilesCoreURL,
		microsegURL,
		webhookURL,
		redisClient,
		harborClient,
		ecCli,
	)
	// go logWorker(es, ch)

	return r
}

func logWorker(es *elastic.ESClient, ch chan model.AccessLog) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	for {
		al := <-ch
		cstZone := time.FixedZone("CST", 8*3600)
		indexStr := "access_" + time.Now().In(cstZone).Format("2006-01-02")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		esCli, err := es.Get()
		if err != nil {
			logging.Get().Err(err).Msg("init es error")
			continue
		}

		_, err = esCli.Index().Index(indexStr).BodyJson(al).Do(ctx)
		if err != nil {
			logging.Get().Info().Msgf("ES  write es error：%s", err)
		}
		cancel()
	}
}

func AccessMiddlewares(ch chan model.AccessLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				al        model.AccessLog
				headerMap map[string][]string
			)

			headerData, _ := json.Marshal(r.Header)
			err := json.Unmarshal(headerData, &headerMap)
			if err != nil {
				logging.Get().Err(err).Msg("unmarshal err")
				next.ServeHTTP(w, r)
				return
			}
			delete(headerMap, "Authorization")
			body, _ := ioutil.ReadAll(r.Body)

			token, claims, err := jwtauth.FromContext(r.Context())
			if err == nil {
				if token == nil || !token.Valid {
				} else {
					username, _ := claims["user_name"].(string)
					al.Username = username
				}
			}

			al.Header = headerMap
			al.Body = string(body)
			al.Method = r.Method
			al.RemoteAddr = r.RemoteAddr
			al.Host = r.Host
			al.RequestURI = r.RequestURI
			al.Time = time.Now()
			select {
			case ch <- al:
				r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
				next.ServeHTTP(w, r)
			case <-time.After(1 * time.Second):
				logging.Get().Error().Msg("access log write chan timeout")
			}

		})
	}
}

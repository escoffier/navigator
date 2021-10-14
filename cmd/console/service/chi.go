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
	"github.com/gorilla/securecookie"
	elastic "github.com/olivere/elastic/v7"
	"gitlab.com/tensorsecurity-rd/go-pkg/pb"

	"gitlab.com/piccolo_su/vegeta/cmd/console/api"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

func setupChiRouter(
	ctx context.Context,
	mongodb *mongotools.DatabaseWrapper,
	postgresDB *rdbtools.GormWrapper,
	es *elastic.Client,
	scannerURL string,
	secProfilesCoreURL string,
	microsegURL string,
	webhookURL string,
	httpLoggerDisabled bool,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	emailOpts *flag.EmailOpts,
	ecCli pb.EventsCenterBizServiceClient,
) http.Handler {
	ch := make(chan model.AccessLog, 1000)
	tokenAuth := jwtauth.New("HS256", securecookie.GenerateRandomKey(64), nil)
	r := chi.NewRouter()
	r.Use(jwtauth.Verifier(tokenAuth))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Compress(5))
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(lang.AcceptLanguageMiddleware)
	r.Use(AccessMiddlewares(ch))
	if !httpLoggerDisabled {
		r.Use(middleware.Logger)
	}

	api.SetupRoutes(ctx, r, 24*time.Hour,
		tokenAuth,
		mongodb,
		postgresDB,
		scannerURL,
		secProfilesCoreURL,
		microsegURL,
		webhookURL,
		redisClient,
		harborClient,
		emailOpts,
		ecCli,
	)
	go logWorker(es, ch)

	return r
}

func logWorker(es *elastic.Client, ch chan model.AccessLog) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	for {
		al := <-ch
		cstZone := time.FixedZone("CST", 8*3600)
		indexStr := "access_" + time.Now().In(cstZone).Format("2006-01-02")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := es.Index().Index(indexStr).BodyJson(al).Do(ctx)
		if err != nil {
			logging.GetLogger().Info().Msgf("ES  write es error：%s", err)
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
			json.Unmarshal(headerData, &headerMap)
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
				logging.GetLogger().Error().Msg("access log write chan timeout")
			}

		})
	}
}

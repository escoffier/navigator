package service

import (
	"context"
	"net/http"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
)

func setupChiRouter(
	ctx context.Context,
	redclair *component.RedClairService,
	mongodb *mongo.Database,
	httpLoggerDisabled bool,
	harborClient *harbor.HarborRESTClient,
	redisClient *redis.Client,
	virusScan *component.VirusScan,
	scannerDB *component.ScannerDB,
) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Compress(5))
	if !httpLoggerDisabled {
		r.Use(middleware.Logger)
	}

	api.SetupRoutes(ctx, r, redclair, mongodb, harborClient, redisClient, virusScan, scannerDB)

	return r
}

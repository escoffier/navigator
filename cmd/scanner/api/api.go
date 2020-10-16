package api

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
)

type api struct {
	ctx      context.Context
	redclair *component.RedClairService
	harbor   *component.HarborRESTClient
	mongodb  *mongo.Database
}

func newAPI(
	ctx context.Context,
	redclair *component.RedClairService,
	harbor *component.HarborRESTClient,
	mongodb *mongo.Database,
) *api {
	return &api{
		ctx:      ctx,
		redclair: redclair,
		harbor:   harbor,
		mongodb:  mongodb,
	}
}

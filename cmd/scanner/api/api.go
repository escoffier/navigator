package api

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
)

type api struct {
	ctx      context.Context
	redclair *component.RedClairService
	mongodb  *mongo.Database
}

func newAPI(
	ctx context.Context,
	redclair *component.RedClairService,
	mongodb *mongo.Database,
) *api {
	return &api{
		ctx:      ctx,
		redclair: redclair,
		mongodb:  mongodb,
	}
}

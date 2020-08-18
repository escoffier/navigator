package api

import (
	"context"

	"go.etcd.io/etcd/clientv3"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
)

type api struct {
	ctx        context.Context
	etcdClient *clientv3.Client
	redclair   *component.RedClair
	mongodb    *mongo.Database
}

func newAPI(
	ctx context.Context,
	etcdClient *clientv3.Client,
	redclair *component.RedClair,
	mongodb *mongo.Database,
) *api {
	return &api{
		ctx:        ctx,
		etcdClient: etcdClient,
		redclair:   redclair,
		mongodb:    mongodb,
	}
}

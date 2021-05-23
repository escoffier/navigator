package util

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
)

func NewMongoClient(username, password, endpoint, database string) (*mongotools.DatabaseWrapper, error) {
	var mongoURI string
	if username != "" && password != "" {
		mongoURI = fmt.Sprintf("mongodb://%s:%s@%s/?authSource=%s", username, password, endpoint, database)
	} else {
		mongoURI = fmt.Sprintf("mongodb://%s/?authSource=%s", endpoint, database)

	}
	mongoClientOptions := options.Client().ApplyURI(mongoURI)
	mongoClientOptions.SetPoolMonitor(&event.PoolMonitor{
		Event: mongotools.PoolMonitorFunc,
	})
	mongoClientOptions.SetWriteConcern(writeconcern.New(writeconcern.WMajority()))
	mongoClientOptions.SetReadConcern(readconcern.Majority())
	mongoClientOptions.SetMaxPoolSize(50)
	mongoClientOptions.SetMaxConnIdleTime(10 * time.Minute)
	mongoClientOptions.SetConnectTimeout(1 * time.Second)
	mongoClientOptions.SetMinPoolSize(5)
	clientWrapper, err := mongotools.NewMongoClient(mongoClientOptions, 1*time.Second)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err = clientWrapper.Connect(ctx); err != nil {
		return nil, err
	}

	return clientWrapper.Database(database), nil
}

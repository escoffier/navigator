package main

import (
	"context"
	"flag"

	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	grpcPort = flag.Int("gport", 8080, "The grpc port")
)

func main() {
	if !flag.Parsed() {
		flag.Parse()
	}

	if err := StartKafkaProxy(context.Background(), *grpcPort); err != nil {
		logging.Get().Err(err).Msg("start error")
		panic(err)
	}
}

package eventcenter_helper

import (
	"os"

	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func NewClientFromEnv() (pb.EventsCenterCollectionServiceClient, error) {
	c, err := credentials.NewClientTLSFromFile(
		GetEnvWithDefault("GRPC_CERT_PATH", "/auth/server/tls.crt"),
		GetEnvWithDefault("GRPC_CERT_SERVER_NAME", "eventcenter"))
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(
		GetEnvWithDefault("EVENT_GRPC_URL", "eventcenter:9090"),
		grpc.WithTransportCredentials(c))
	if err != nil {
		return nil, err
	}
	return pb.NewEventsCenterCollectionServiceClient(conn), nil
}

func GetEnvWithDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

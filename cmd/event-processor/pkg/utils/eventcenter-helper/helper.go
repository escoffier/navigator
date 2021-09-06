package eventcenter_helper

import (
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os"
)

func NewClientFromEnv() (pb.EventsCenterCollectionServiceClient, error) {
	c, err := credentials.NewClientTLSFromFile(
		GetEnvWithDefault("GRPC_CERT_PATH", "/auth/server/tls.crt"),
		GetEnvWithDefault("GRPC_CERT_SERVER_NAME", "tensorsec-eventcenter"))
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(
		GetEnvWithDefault("EVENT_GRPC_URL", "tensorsec-eventcenter:9090"),
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

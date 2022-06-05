package echelper

import (
	"context"
	"time"

	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	GrpcCertPathEnv           = "EVENT_GRPC_CERT_PATH"
	DefaultGrpcCertPath       = "/auth/server/tls.crt"
	GrpcCertServerNameEnv     = "EVENT_GRPC_CERT_SERVER_NAME"
	DefaultGrpcCertServerName = "eventcenter"
	EventGrpcURLEnv           = "EVENT_GRPC_URL"
	DefaultEventGrpcURL       = "eventcenter:9090"
)

const (
	ErrCodeBadRequest = 400
)

type UUIDGenerator interface {
	GenerateUUID() uint64
}

type GrpcConf struct {
	CertPath       string
	CertServerName string
	URL            string
}

type EventCenterConfig struct {
	uuidGenerator UUIDGenerator
	grpcConf      *GrpcConf
}

type EventCenterClientOption func(conf *EventCenterConfig)

type EventCenterClient struct {
	cli           pb.EventsCenterCollectionServiceClient
	uuidGenerator UUIDGenerator
}

func NewEventCenterClient(options ...EventCenterClientOption) (*EventCenterClient, error) {
	var conf EventCenterConfig
	for _, option := range options {
		option(&conf)
	}

	var grpcClient pb.EventsCenterCollectionServiceClient
	var uuidGenerator UUIDGenerator
	var err error
	if conf.grpcConf != nil {
		grpcClient, err = NewGRPCClient(conf.grpcConf)
	} else {
		grpcClient, err = NewGRPCClientFromEnv()
	}

	if err != nil {
		return nil, err
	}

	if conf.uuidGenerator != nil {
		uuidGenerator = conf.uuidGenerator
	} else {
		uuidGenerator, err = uuid.NewGenerator()
		if err != nil {
			return nil, err
		}
	}

	return &EventCenterClient{
		cli:           grpcClient,
		uuidGenerator: uuidGenerator,
	}, nil
}

func NewGRPCClientFromEnv() (pb.EventsCenterCollectionServiceClient, error) {
	conf := &GrpcConf{
		CertPath:       util.GetEnvWithDefault(GrpcCertPathEnv, DefaultGrpcCertPath),
		CertServerName: util.GetEnvWithDefault(GrpcCertServerNameEnv, DefaultGrpcCertServerName),
		URL:            util.GetEnvWithDefault(EventGrpcURLEnv, DefaultEventGrpcURL),
	}

	return NewGRPCClient(conf)
}

func NewGRPCClient(conf *GrpcConf) (pb.EventsCenterCollectionServiceClient, error) {
	c, err := credentials.NewClientTLSFromFile(conf.CertPath, conf.CertServerName)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(conf.URL, grpc.WithTransportCredentials(c))
	if err != nil {
		return nil, err
	}
	return pb.NewEventsCenterCollectionServiceClient(conn), nil
}

func (c *EventCenterClient) SendNotification(ctx context.Context, ruleKey *pb.RuleKey, context *pb.Context) error {
	req := &pb.SendNotificationReq{
		RuleKey:       ruleKey,
		NotifyContext: context,
		UUID:          c.uuidGenerator.GenerateUUID(),
		Timestamp:     time.Now().Unix(),
	}
	_, err := c.cli.SendNotification(ctx, req)
	return err
}

func (c *EventCenterClient) AddDetectionRule(ctx context.Context, rule *pb.DetectionRule) error {
	req := &pb.AddDetectionRuleReq{
		Rule: rule,
	}
	return util.RetryWithBackoff(ctx, func() error {
		_, err := c.cli.AddDetectionRule(ctx, req)
		return err
	}, retry.RetryIf(c.isRetryErr))
}

func (c *EventCenterClient) ResetCategoryRules(ctx context.Context, module, category string, rules []*pb.DetectionRule) error {
	req := &pb.ResetCategoryRulesReq{
		Module:   module,
		Category: category,
		Rules:    rules,
	}
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	_, err := c.cli.ResetCategoryRules(tctx, req)
	return err
}

func (c *EventCenterClient) isRetryErr(err error) bool {
	if code, ok := status.FromError(err); ok && code.Code() == ErrCodeBadRequest {
		return false
	}
	return true
}

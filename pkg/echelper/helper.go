package echelper

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"google.golang.org/grpc/status"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

// type EventCenterConfig struct {
// 	uuidGenerator UUIDGenerator
// 	grpcConf      *GrpcConf
// }
//
// type EventCenterClientOption func(conf *EventCenterConfig)

type EventCenterClient struct {
	cli           pb.EventsCenterCollectionServiceClient
	uuidGenerator UUIDGenerator
}

// func NewEventCenterClient(options ...EventCenterClientOption) (*EventCenterClient, error) {
// 	var conf EventCenterConfig
// 	for _, option := range options {
// 		option(&conf)
// 	}
//
// 	var grpcClient pb.EventsCenterCollectionServiceClient
// 	var uuidGenerator UUIDGenerator
// 	var err error
// 	if conf.grpcConf != nil {
// 		grpcClient, err = NewGRPCClient(conf.grpcConf)
// 	} else {
// 		grpcClient, err = NewGRPCClientFromEnv()
// 	}
//
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	if conf.uuidGenerator != nil {
// 		uuidGenerator = conf.uuidGenerator
// 	} else {
// 		uuidGenerator, err = uuid.NewGenerator()
// 		if err != nil {
// 			return nil, err
// 		}
// 	}
//
// 	return &EventCenterClient{
// 		cli:           grpcClient,
// 		uuidGenerator: uuidGenerator,
// 	}, nil
// }

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

func (c *SherlockClient) getURL(path string) string {
	base := os.Getenv("SHERLOCK_URL")
	switch path {
	case "ResetCategoryRules":
		return base + "/api/v1/palace/internal/rules/reset"
	case "AddDetectionRule":
		return base + "/api/v1/palace/internal/rules"
	}
	return base
}

type SherlockClient struct{}

func NewSherlockClient() SherlockClient {
	return SherlockClient{}
}

func (c *SherlockClient) AddDetectionRule(ctx context.Context, rule *pb.DetectionRule) error {
	logging.GetLogger().Debug().Msgf("AddDetectionRule start, url:%s, rule:%v", c.getURL("AddDetectionRule"), rule)

	type Request struct {
		Rule *pb.DetectionRule `json:"Rule"`
	}

	jsonBytes, err := json.Marshal(Request{
		Rule: rule,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.getURL("AddDetectionRule"), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	logging.GetLogger().Debug().Msgf("AddDetectionRule end, url:%s, req:%s, rsp:%s", c.getURL("AddDetectionRule"), string(jsonBytes), string(body))

	return nil
}

func (c *SherlockClient) ResetCategoryRules(ctx context.Context, category string, rules []*pb.DetectionRule) error {

	logging.GetLogger().Debug().Msgf("ResetCategoryRules start, url:%s, category:%s, rules:%v", c.getURL("ResetCategoryRules"), category, rules)

	type Request struct {
		Category string              `json:"Category"`
		Rules    []*pb.DetectionRule `json:"Rules"`
	}

	jsonBytes, err := json.Marshal(Request{
		Category: category,
		Rules:    rules,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.getURL("ResetCategoryRules"), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	logging.GetLogger().Debug().Msgf("ResetCategoryRules end, url:%s, req:%s, rsp:%s", c.getURL("ResetCategoryRules"), string(jsonBytes), string(body))

	return nil
}

func (c *EventCenterClient) isRetryErr(err error) bool {
	if code, ok := status.FromError(err); ok && code.Code() == ErrCodeBadRequest {
		return false
	}
	return true
}

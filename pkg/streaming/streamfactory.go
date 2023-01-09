package rpcstream

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"github.com/google/uuid"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/util/wait"
)

type StreamFactoryOption func(*streamFactory) *streamFactory

type MessageHandler interface {
	OnCreate(Stream, string, protoreflect.ProtoMessage)
	OnRead(Stream, string, protoreflect.ProtoMessage)
	OnUpdate(Stream, string, protoreflect.ProtoMessage)
	OnDelete(Stream, string, protoreflect.ProtoMessage)
}

type MessageHandlerFuncs struct {
	CreateFunc func(Stream, string, protoreflect.ProtoMessage)
	ReadFunc   func(Stream, string, protoreflect.ProtoMessage)
	UpdateFunc func(Stream, string, protoreflect.ProtoMessage)
	DeleteFunc func(Stream, string, protoreflect.ProtoMessage)
}

func (mf *MessageHandlerFuncs) OnCreate(s Stream, reqID string, msg protoreflect.ProtoMessage) {
	if mf.CreateFunc != nil {
		mf.CreateFunc(s, reqID, msg)
	}
}

func (mf *MessageHandlerFuncs) OnRead(s Stream, reqID string, msg protoreflect.ProtoMessage) {
	if mf.ReadFunc != nil {
		mf.ReadFunc(s, reqID, msg)
	}
}

func (mf *MessageHandlerFuncs) OnUpdate(s Stream, reqID string, msg protoreflect.ProtoMessage) {
	if mf.UpdateFunc != nil {
		mf.UpdateFunc(s, reqID, msg)
	}
}

func (mf *MessageHandlerFuncs) OnDelete(s Stream, reqID string, msg protoreflect.ProtoMessage) {
	if mf.DeleteFunc != nil {
		mf.DeleteFunc(s, reqID, msg)
	}
}

const defaultNodeKey = "default"

type MessageStream interface {
	MessageStreamClient
	Start()
	AddHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error
	AddHandlerFunc(msg protoreflect.ProtoMessage, f ProcessFunc) error
	Response(stream Stream, reqUUID string, resp protoreflect.ProtoMessage) error
}

type StreamFactory interface {
	Server(network string, address string) MessageStream
	Client(remoteAddress string) MessageStream
}

type messageStream struct {
	streams    map[string]Stream
	processors map[string]ProcessFunc
	hanlders   map[string]MessageHandler
	noderKey   string

	streamLock sync.Mutex
}

type messageStreamServer struct {
	network string
	address string
	messageStream
}

type messageStreamClient struct {
	remoteAddress string
	pbClient      pb.ClusterServiceClient
	messageStream
}

type streamFactory struct {
	NodeKey string
}

func WithPodNameKey() StreamFactoryOption {
	return func(sf *streamFactory) *streamFactory {
		podName := os.Getenv("MY_POD_NAME")
		namespace := os.Getenv("MY_POD_NAMESPACE")
		sf.NodeKey = fmt.Sprintf("%s/%s", namespace, podName)
		return sf
	}
}

func WithClusterKey(clusterKey string) StreamFactoryOption {
	return func(sf *streamFactory) *streamFactory {
		sf.NodeKey = clusterKey
		return sf
	}
}

func NewStreamFactory(options ...StreamFactoryOption) StreamFactory {
	factory := &streamFactory{}

	for _, opt := range options {
		factory = opt(factory)
	}
	return factory
}

func (s *messageStreamServer) SendMessage(stream pb.ClusterService_SendMessageServer) error {
	stopChan := make(chan struct{})
	in, err := stream.Recv()
	if err == io.EOF {
		return err
	}
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("new stream from : %s established", in.NodeKey)
	rs := NewServerStream(stream)

	s.streamLock.Lock()
	s.streams[in.NodeKey] = rs
	for name, fun := range s.processors {
		s.streams[in.NodeKey].AddHandlerFunc(name, fun)
	}
	for name, handler := range s.hanlders {
		s.streams[in.NodeKey].AddHandler(name, handler)
	}
	s.streamLock.Unlock()

	go rs.Run(stopChan)

	logging.Get().Info().Msg("begin dispatching message")
	rs.Dispatch()

	logging.Get().Info().Msgf("lost stream: %s", in.NodeKey)
	delete(s.streams, in.NodeKey)

	return nil
}

func (f *streamFactory) Server(network string, address string) MessageStream {
	return &messageStreamServer{
		network: network,
		address: address,
		messageStream: messageStream{
			streams:    make(map[string]Stream, 0),
			processors: make(map[string]ProcessFunc, 0),
			hanlders:   make(map[string]MessageHandler, 0),
			noderKey:   f.NodeKey,
		},
	}
}

func (s *messageStream) AddHandlerFunc(msg protoreflect.ProtoMessage, f ProcessFunc) error {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()

	msgType := reflect.TypeOf(msg)
	fmt.Println(msgType.Name())

	messageName := string(msg.ProtoReflect().Descriptor().Name())
	s.processors[messageName] = f
	for _, stream := range s.streams {
		stream.AddHandlerFunc(messageName, f)
	}
	return nil

}

func (s *messageStream) AddHandler(msg protoreflect.ProtoMessage, handler MessageHandler) error {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()

	messageName := string(msg.ProtoReflect().Descriptor().Name())
	logging.Get().Info().Msgf("add handler for : %s", messageName)
	s.hanlders[messageName] = handler
	for _, stream := range s.streams {
		stream.AddHandler(messageName, handler)
	}
	return nil

}

func (s *messageStream) Request(ctx context.Context, nodeKey string, msgType pb.MessageType, req protoreflect.ProtoMessage, ack bool) (protoreflect.ProtoMessage, error) {
	payload, err := anypb.New(req)
	if err != nil {
		return nil, err
	}

	r := &pb.ClusterMessage{
		Topic:       "topic",
		MessageType: msgType,
		ReqUUID:     uuid.New().String(),
		NodeKey:     s.noderKey,
		Payload:     payload,
	}

	stream := s.streams[nodeKey]
	if stream == nil {
		return nil, fmt.Errorf("not found stream: %s", nodeKey)
	}
	stream.AddSession(r.ReqUUID)
	logging.Get().Info().Msgf("sending message: %s", r.String())
	err = stream.Send(r)
	if err != nil {
		return nil, err
	}
	if ack {
		select {
		case resp := <-stream.Response(r.ReqUUID):
			return resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, nil
}

func (s *messageStream) Publish(ctx context.Context, nodeKeys []string, msgType pb.MessageType, req protoreflect.ProtoMessage, ack bool) error {
	for _, nodeKey := range nodeKeys {
		_, err := s.Request(ctx, nodeKey, msgType, req, false)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *messageStream) Response(stream Stream, reqUUID string, resp protoreflect.ProtoMessage) error {
	payload, err := anypb.New(resp)
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("resp uuid %s", reqUUID)
	req := &pb.ClusterMessage{
		Topic:   "topic",
		ReqUUID: reqUUID,
		Payload: payload,
	}
	return stream.Send(req)
}

func (s *messageStreamServer) Start() {
	lis, err := net.Listen(s.network, s.address)
	if err != nil {
		panic(err)
	}
	srv := grpc.NewServer()
	pb.RegisterClusterServiceServer(srv, s)
	go srv.Serve(lis)
}

func (f *streamFactory) Client(remoteAddress string) MessageStream {
	return &messageStreamClient{
		remoteAddress: remoteAddress,
		messageStream: messageStream{
			streams:    make(map[string]Stream, 0),
			processors: make(map[string]ProcessFunc, 3),
			hanlders:   make(map[string]MessageHandler, 0),
			noderKey:   f.NodeKey,
		},
	}
}

func (c *messageStreamClient) Start() {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	conn, err := grpc.Dial(c.remoteAddress, opts...)
	if err != nil {
		logging.Get().Err(err).Msg("dial peer err")
		return
	}
	c.pbClient = pb.NewClusterServiceClient(conn)

	stopChan := make(chan struct{})
	go func() {
		wait.PollImmediateUntil(time.Second*5, func() (done bool, err error) {
			stream, err := c.pbClient.SendMessage(context.Background())
			if err != nil {
				logging.Get().Err(err).Msg("calling grpc server err")
				return false, nil
			}
			cs := NewClientStream(stream)

			go cs.Run(stopChan)

			c.streamLock.Lock()
			c.streams[defaultNodeKey] = cs
			for name, fun := range c.processors {
				c.streams[defaultNodeKey].AddHandlerFunc(name, fun)
			}
			for name, handler := range c.hanlders {
				c.streams[defaultNodeKey].AddHandler(name, handler)
			}
			c.streamLock.Unlock()

			c.Request(context.Background(), defaultNodeKey, pb.MessageType_CREATE, &pb.Register{
				NodeKey: defaultNodeKey,
			}, false)
			cs.Dispatch()

			logging.Get().Info().Msg("connection lost, will try to reconnect")
			c.streamLock.Lock()
			delete(c.streams, defaultNodeKey)
			c.streamLock.Unlock()

			return false, nil
		}, stopChan)
	}()

}

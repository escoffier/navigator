package rpcstream

import (
	"fmt"
	"io"
	"sync"

	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/client-go/tools/cache"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

type ProcessFunc func(Stream, string, pb.MessageType, protoreflect.ProtoMessage) error

type ReceiveFunc func() (*pb.ClusterMessage, error)
type SenderFunc func(*pb.ClusterMessage) error
type Stream interface {
	Dispatch() error
	AddHandler(StreammsgName string, handler MessageHandler) error
	AddHandlerFunc(StreammsgName string, f ProcessFunc) error
	AddSession(id string)
	Send(*pb.ClusterMessage) error
	Response(reqUUID string) chan protoreflect.ProtoMessage
	SendResponse(reqUUID string, resp protoreflect.ProtoMessage) error
	Run(stopChan chan struct{})
	Clean()
}

type baseStream struct {
	stopChan    chan struct{}
	processors  map[string]ProcessFunc
	handlers    map[string]MessageHandler
	sessions    map[string]chan protoreflect.ProtoMessage
	queue       cache.Queue
	sessionLock sync.RWMutex
	Receiver    ReceiveFunc
	Sender      SenderFunc
}

func (s *baseStream) AddHandler(msgName string, handler MessageHandler) error {
	logging.Get().Debug().Msgf("add handler for %s", msgName)
	s.handlers[msgName] = handler
	return nil
}

func (s *baseStream) AddHandlerFunc(msgName string, f ProcessFunc) error {
	logging.Get().Debug().Msgf("add handler for %s", msgName)
	s.processors[msgName] = f
	return nil
}

func (s *baseStream) AddSession(id string) {
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()

	s.sessions[id] = make(chan protoreflect.ProtoMessage)
}

func (s *baseStream) Send(msg *pb.ClusterMessage) error {
	return s.queue.Add(msg)
}

func (s *baseStream) Response(reqUUID string) chan protoreflect.ProtoMessage {
	s.sessionLock.RLock()
	defer s.sessionLock.RUnlock()
	resp := s.sessions[reqUUID]

	return resp
}

func (s *baseStream) SendResponse(reqUUID string, resp protoreflect.ProtoMessage) error {
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
	return s.Send(req)
}

func (s *baseStream) Dispatch() error {
	for {
		select {
		case <-s.stopChan:
			return nil
		default:
		}
		in, err := s.Receiver()

		if err == io.EOF {
			logging.Get().Err(err).Msg("close Dispatch")
			return nil
		}
		if err != nil {
			logging.Get().Err(err).Msg("close Dispatch")
			return err
		}

		logging.Get().Info().Msgf("received message %s", in.String())
		m, err := in.Payload.UnmarshalNew()
		if err != nil {
			logging.Get().Err(err).Msg("Unmarshal payload err")
			continue
		}

		// process request message
		fn, ok := s.processors[string(m.ProtoReflect().Descriptor().Name())]
		if ok {
			go fn(s, in.ReqUUID, in.MessageType, m)
			continue
		}
		hanlder, ok := s.handlers[string(m.ProtoReflect().Descriptor().Name())]
		if ok {
			go func() {
				switch in.MessageType {
				case pb.MessageType_CREATE:
					hanlder.OnCreate(s, in.ReqUUID, m)
				case pb.MessageType_READ:
					hanlder.OnRead(s, in.ReqUUID, m)
				case pb.MessageType_UPDATE:
					hanlder.OnUpdate(s, in.ReqUUID, m)
				case pb.MessageType_DELETE:
					hanlder.OnDelete(s, in.ReqUUID, m)
				}

			}()
			continue
		}

		// process response
		s.sessionLock.RLock()
		respChan, ok := s.sessions[in.ReqUUID]
		if ok {
			respChan <- m
			close(respChan)
		} else {
			fmt.Println("session has expired")
		}
		s.sessionLock.RUnlock()

	}
}

func (s *baseStream) Run(stopChan chan struct{}) {
	for {
		_, err := s.queue.Pop(func(obj interface{}) error {
			msg := obj.(*pb.ClusterMessage)
			s.Sender(msg)
			return nil
		})
		if err != nil {
			if err == cache.ErrFIFOClosed {
				logging.Get().Info().Msgf("cache close")
				return
			}
		}
	}
}

func (s *baseStream) Clean() {
	s.queue.Close() // 标记位置位，不涉及重复关闭判断
}

type serverStream struct {
	stream pb.ClusterService_SendMessageServer
	baseStream
}

func NewServerStream(stream pb.ClusterService_SendMessageServer) Stream {
	return &serverStream{
		stream: stream,
		baseStream: baseStream{
			stopChan:   make(chan struct{}),
			processors: make(map[string]ProcessFunc, 0),
			handlers:   make(map[string]MessageHandler, 0),
			sessions:   make(map[string]chan protoreflect.ProtoMessage),
			queue: cache.NewFIFO(func(obj interface{}) (string, error) {
				msg := obj.(*pb.ClusterMessage)
				return msg.GetReqUUID(), nil
			}),
			Receiver: func() (*pb.ClusterMessage, error) {
				return stream.Recv()
			},
			Sender: func(cm *pb.ClusterMessage) error {
				return stream.Send(cm)
			},
		},
	}
}

type clientStream struct {
	stream pb.ClusterService_SendMessageClient
	baseStream
}

func NewClientStream(stream pb.ClusterService_SendMessageClient) Stream {
	return &clientStream{
		stream: stream,
		baseStream: baseStream{
			stopChan:   make(chan struct{}),
			processors: make(map[string]ProcessFunc, 0),
			handlers:   make(map[string]MessageHandler, 0),
			sessions:   make(map[string]chan protoreflect.ProtoMessage),
			queue: cache.NewFIFO(func(obj interface{}) (string, error) {
				msg := obj.(*pb.ClusterMessage)
				return msg.GetReqUUID(), nil
			}),
			Receiver: func() (*pb.ClusterMessage, error) {
				return stream.Recv()
			},
			Sender: func(cm *pb.ClusterMessage) error {
				return stream.Send(cm)
			},
		},
	}
}

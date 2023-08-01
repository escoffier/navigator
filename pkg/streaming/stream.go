package rpcstream

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

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
	AddSession(id string, ack bool)
	DelSession(id string)
	DelAllSession()
	Send(*pb.ClusterMessage) error
	Response(ctx context.Context, reqUUID string) (protoreflect.ProtoMessage, error)
	// Response(reqUUID string) chan protoreflect.ProtoMessage
	SendResponse(reqUUID string, resp protoreflect.ProtoMessage) error
	Run(stopChan chan struct{})
	Dump() map[string]interface{}
	Clean()
}

type Session struct {
	ack      bool
	dataCh   chan protoreflect.ProtoMessage
	creareAt time.Time
}

type baseStream struct {
	stopChan    chan struct{}
	processors  map[string]ProcessFunc
	handlers    map[string]MessageHandler
	sessions    map[string]*Session
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

func (s *baseStream) DelAllSession() {
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	for k, se := range s.sessions {
		close(se.dataCh)
		delete(s.sessions, k)
	}
}

func (s *baseStream) DelSession(id string) {
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	// v, ok := s.sessions[id]
	// if ok {
	// 	close(v.dataCh)
	// }
	delete(s.sessions, id)
}

func (s *baseStream) AddSession(id string, ack bool) {
	logging.Get().Debug().Str("sessionID", id).Msg("start add session")
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	se := &Session{
		ack:      ack,
		dataCh:   make(chan protoreflect.ProtoMessage, 1),
		creareAt: time.Now(),
	}
	s.sessions[id] = se
}

func (s *baseStream) Send(msg *pb.ClusterMessage) error {
	return s.queue.Add(msg)
}

func (s *baseStream) getSession(reqUUID string) (*Session, bool) {
	s.sessionLock.RLock()
	defer s.sessionLock.RUnlock()
	resp, ok := s.sessions[reqUUID]
	return resp, ok
}

func (s *baseStream) Response(ctx context.Context, reqUUID string) (protoreflect.ProtoMessage, error) {
	session, ok := s.getSession(reqUUID)
	if ok {
		select {
		case r := <-session.dataCh:
			if r == nil {
				return nil, fmt.Errorf("reqID %v,recv nil resp. session has been removed", reqUUID)
			}
			return r, nil
		case <-ctx.Done():
			logging.Get().Error().Str("reqID", reqUUID).Msg("context timeout")
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("session has expired")
}

func (s *baseStream) SendResponse(reqUUID string, resp protoreflect.ProtoMessage) error {
	payload, err := anypb.New(resp)
	if err != nil {
		return err
	}

	logging.Get().Info().Str("reqID", reqUUID).Msg("stream send rsp")
	req := &pb.ClusterMessage{
		Topic:   "topic",
		ReqUUID: reqUUID,
		Payload: payload,
	}
	return s.Send(req)
}

func (s *baseStream) Dispatch() error {
	for {
		logging.Get().Debug().Msg("dispatch waiting")

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

		m, err := in.Payload.UnmarshalNew()
		if err != nil {
			logging.Get().Err(err).Msg("Unmarshal payload err")
			continue
		}

		logging.Get().Debug().Str("reqID", in.ReqUUID).Msgf("received message: %s", string(m.ProtoReflect().Descriptor().Name()))

		// process request message
		fn, ok := s.processors[string(m.ProtoReflect().Descriptor().Name())]
		if ok {
			go fn(s, in.ReqUUID, in.MessageType, m)
			continue
		}
		handler, ok := s.handlers[string(m.ProtoReflect().Descriptor().Name())]
		//	logging.Get().Info().Msgf("映射handler并处理 %v %v %v", in.MessageType, string(m.ProtoReflect().Descriptor().Name()), ok)
		if ok {
			logging.Get().Debug().Str("reqID", in.ReqUUID).Msg("handler dealing msg")
			go func() {
				switch in.MessageType {
				case pb.MessageType_CREATE:
					handler.OnCreate(s, in.ReqUUID, m)
				case pb.MessageType_READ:
					handler.OnRead(s, in.ReqUUID, m)
				case pb.MessageType_UPDATE:
					handler.OnUpdate(s, in.ReqUUID, m)
				case pb.MessageType_DELETE:
					handler.OnDelete(s, in.ReqUUID, m)
				}

			}()
			continue
		}

		// process response
		func() {
			logging.Get().Info().Str("reqID", in.ReqUUID).Msg("dispatch deal resp data")
			s.sessionLock.RLock()
			defer s.sessionLock.RUnlock()
			session, ok := s.sessions[in.ReqUUID]
			if ok {
				logging.Get().Info().Str("reqID", in.ReqUUID).
					Msgf("dispatch receive resp:[ id: %s, create at: %v, ack: %v ]", in.ReqUUID, session.creareAt, session.ack)
				if session.ack {
					session.ack = false
					session.dataCh <- m
					close(session.dataCh)
				}
			} else {
				logging.Get().Error().Str("reqID", in.ReqUUID).Msg("not found session")
			}
		}()
	}
}

func (s *baseStream) Run(stopChan chan struct{}) {
	for {
		_, err := s.queue.Pop(func(obj interface{}) error {
			logging.Get().Debug().Msg("queue pop,ready to send")

			msg := obj.(*pb.ClusterMessage)
			s.Sender(msg)
			return nil
		})
		if err != nil {
			if err == cache.ErrFIFOClosed {
				logging.Get().Info().Msgf("cache close")
				return
			}
			logging.Get().Err(err).Msg("queue pop err")
		}
	}
}

func (s *baseStream) Clean() {
	s.queue.Close() // 标记位置位，不涉及重复关闭判断
}

func (s *baseStream) Dump() map[string]interface{} {
	s.sessionLock.RLock()
	defer s.sessionLock.RUnlock()
	info := make(map[string]interface{})
	for k, v := range s.sessions {
		info[k] = struct {
			Ack      bool
			CreateAt time.Time
		}{
			Ack:      v.ack,
			CreateAt: v.creareAt,
		}
	}
	return info
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
			sessions:   make(map[string]*Session),
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
			sessions:   make(map[string]*Session),
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

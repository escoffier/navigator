package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
)

// blocking
func StartKafkaProxy(ctx context.Context, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logging.Get().Err(err).Msg("failed to listen")
		return err
	}

	mqFactory := mq.GetClientFactory()
	mqWriter, err := mqFactory.Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("Init mq error")
		return err
	}

	s := grpc.NewServer()
	ks := &KafkaProxyServer{
		inputChan: make(chan *pb.Message, 50),
		mqWriter:  mqWriter,
	}
	ks.asyncLoop()
	pb.RegisterMQProxyServer(s, ks)

	if err := s.Serve(listener); err != nil {
		logging.Get().Err(err).Int("port", port).Msg("serve error")
		return err
	}
	return nil
}

type KafkaProxyServer struct {
	pb.UnimplementedMQProxyServer

	inputChan chan *pb.Message
	mqWriter  mq.Writer
}

func (s *KafkaProxyServer) send(ctx context.Context, msg *pb.Message) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	select {
	case s.inputChan <- msg:
		return nil
	case <-ctx.Done():
		return errors.New("send timeout")
	}
}

func (s *KafkaProxyServer) forward(ctx context.Context, msg *pb.Message) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("forward to kafka panic: %v", r)
		}
	}()

	headers := make([]kafka.Header, len(msg.Headers))
	for i, h := range msg.Headers {
		headers[i].Key = h.Key
		headers[i].Value = h.Value
	}
	return s.mqWriter.Write(ctx, msg.Topic, kafka.Message{
		Topic:   msg.Topic,
		Key:     msg.Key,
		Value:   msg.Value,
		Headers: headers,
	})
}
func (s *KafkaProxyServer) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic: %v", r)
			}
		}()

		for m := range s.inputChan {
			if err := s.forward(context.Background(), m); err != nil {
				logging.Get().Err(err).Str("topic", m.Topic).Str("Key", string(m.Key)).Str("val", string(m.Value)).Msg("failed to forward")
			}
		}
	}()
}
func (s *KafkaProxyServer) Produce(stream pb.MQProxy_ProduceServer) error {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			logging.Get().Err(err).Msg("produce stream error")
			return err
		}

		err = s.send(context.Background(), in)
		if err != nil {
			logging.Get().Err(err).Str("key", string(in.Key)).Str("topic", in.Topic).Str("val", string(in.Value)).Msg("failed to send")
		}
	}
}

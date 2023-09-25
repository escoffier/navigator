package rpcstream

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func Test_messageStream_Request(t *testing.T) {
	type fields struct {
		streams    map[string]Stream
		processors map[string]ProcessFunc
		hanlders   map[string]MessageHandler
		KeyToLabel map[string]string
		noderKey   string
		Label      string
		streamLock sync.Mutex
	}
	type args struct {
		ctx     context.Context
		nodeKey string
		msgType pb.MessageType
		req     protoreflect.ProtoMessage
		ack     bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    protoreflect.ProtoMessage
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &messageStream{
				streams:    tt.fields.streams,
				processors: tt.fields.processors,
				hanlders:   tt.fields.hanlders,
				KeyToLabel: tt.fields.KeyToLabel,
				noderKey:   tt.fields.noderKey,
				Label:      tt.fields.Label,
				streamLock: tt.fields.streamLock,
			}
			got, err := s.Request(tt.args.ctx, tt.args.nodeKey, tt.args.msgType, tt.args.req, tt.args.ack)
			if (err != nil) != tt.wantErr {
				t.Errorf("messageStream.Request() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("messageStream.Request() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_channel(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), time.Second*5)
	data := make(chan int)
	go func() {
		defer logging.Get().Info().Msg("read goroutine exit")
		select {
		case d := <-data:
			fmt.Printf("receive data: %d\n", d)
		case <-ctx.Done():
			fmt.Println("time out")
		}
		time.Sleep(5 * time.Second)
	}()

	go func() {
		defer logging.Get().Info().Msg("write goroutine exit")
		time.Sleep(time.Second * 7)
		fmt.Println("try to writing data")
		data <- 10

		fmt.Println("write data")
	}()

	time.Sleep(10 * time.Second)
	fmt.Printf("goroutine number: %d\n", runtime.NumGoroutine())

	select {}
}

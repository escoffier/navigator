package main

import (
	"reflect"
	"testing"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	_ "go.uber.org/automaxprocs"
)

func Test_getEventTypeOfMessage(t *testing.T) {
	type args struct {
		m kafka.Message
	}
	tests := []struct {
		name string
		args args
		want model.MessageEventType
	}{
		{
			name: "holmes",
			args: args{
				m: kafka.Message{
					Headers: []kafka.Header{
						{
							Key:   model.MHeaderKeyEventType,
							Value: []byte(model.MEventTypeHolmes),
						},
					},
				},
			},
			want: model.MEventTypeHolmes,
		},
		{
			name: "drift",
			args: args{
				m: kafka.Message{
					Headers: []kafka.Header{
						{
							Key:   model.MHeaderKeyEventType,
							Value: []byte(model.MEventTypeDrift),
						},
					},
				},
			},
			want: model.MEventTypeDrift,
		},
		{
			name: "fallback to default holmes 0",
			args: args{
				m: kafka.Message{
					Headers: []kafka.Header{
						{
							Key:   model.MHeaderKeyEventType,
							Value: []byte("whatever"),
						},
					},
				},
			},
			want: model.MEventTypeHolmes,
		},
		{
			name: "fallback to default holmes 0",
			args: args{
				m: kafka.Message{
					Headers: []kafka.Header{},
				},
			},
			want: model.MEventTypeHolmes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getEventTypeOfMessage(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getEventTypeOfMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

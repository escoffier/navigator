package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func main() {
	logging.Get().SetLevel(zerolog.DebugLevel)
	stream := rpcstream.NewStreamFactory(rpcstream.WithClusterKey("123456")).Client("127.0.0.1:19090")

	stream.AddHandler(&pb.HoneySpotReq{}, &rpcstream.MessageHandlerFuncs{
		CreateFunc: func(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
			h := message.(*pb.HoneySpotReq)
			fmt.Println(h.Name)
			s.SendResponse(reqID, &pb.HoneySpotResp{
				Name:          h.Name,
				StatusMessage: "create successfully",
			})
		},
	})
	stream.Start()
	time.Sleep(time.Second * 5)
	stream.CreateCluster(context.Background(), "default", &pb.ClusterRegister{
		Key:  "123456",
		Name: "test-cluster",
	})
	select {}

}

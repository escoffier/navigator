package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func main() {
	logging.Get().SetLevel(zerolog.DebugLevel)

	stream := rpcstream.NewStreamFactory(rpcstream.WithClusterKey("main")).Server("tcp", ":19090")
	stream.AddHandler(&pb.ClusterRegister{}, &rpcstream.MessageHandlerFuncs{
		CreateFunc: func(s1 rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
			cluster := message.(*pb.ClusterRegister)
			logging.Get().Info().Msg(cluster.String())
			s1.SendResponse(reqID, &pb.CommonReponse{
				Status:        1,
				StatusMessage: "i'am sorry",
			})
		},
		ReadFunc:   func(s1 rpcstream.Stream, s2 string, pm protoreflect.ProtoMessage) {},
		UpdateFunc: func(s1 rpcstream.Stream, s2 string, pm protoreflect.ProtoMessage) {},
		DeleteFunc: func(s1 rpcstream.Stream, s2 string, pm protoreflect.ProtoMessage) {},
	})
	stream.Start()

	time.Sleep(time.Second * 10)

	logging.Get().Info().Msgf("streams: %s", stream.DumpStreams())

	start := time.Now()
	wg := &sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		index := i
		go func() {
			defer wg.Done()
			honeySpot := &pb.HoneySpotReq{
				Namespace: fmt.Sprintf("default-%d", index),
				Name:      uuid.NewString(),
				Image:     "docker.io/test/image:latest",
			}
			resp, err := stream.CreateHoneySpot(context.Background(), "123456", honeySpot)
			if err != nil {
				logging.Get().Err(err).Msg("request err")
				return
			}
			if resp.Name != honeySpot.Name {
				logging.Get().Error().Msgf("unexpect response: %s", resp.String())
			}
		}()
		logging.Get().Info().Msgf("streams: %s", stream.DumpStreams())
	}
	wg.Wait()
	logging.Get().Info().Msgf("elapse time: %v", time.Since(start))
	select {}
}

package imagesec

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"time"

	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type StreamHandler struct {
	ServerStream rpcstream.MessageStream
}

func (sh *StreamHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	msg := message.(*pb.ImageSecReq)
	logging.Get().Info().Str("reqID", reqID).Str("msgID", msg.RequestID).Msg("received image sec stream msg")

	var rspErr error
	var rspMsg string
	forwardMsgFunc := func(req *pb.ImageSecReq) {
		defer func() {
			orgResp := &pb.ImageSecResp{}
			if rspErr != nil {
				orgResp.Status = 1
				orgResp.StatusMessage = rspMsg
			} else {
				orgResp.Status = 0
				orgResp.StatusMessage = "ok"
			}
			if err := s.SendResponse(reqID, orgResp); err != nil {
				logging.Get().Err(err).Str("reqID", reqID).Str("msgID", req.RequestID).Msg("failed to send response to scanner")
			} else {
				logging.Get().Info().Str("reqID", reqID).Str("msgID", req.RequestID).Msg("send response to scanner ok")
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(util.ImageSecGrpcTimeOut())*time.Second)
		defer cancel()
		resp, err := sh.ServerStream.PublishImageSecMsgByClusterKey(ctx, req.ClusterKey, req)
		if err != nil {
			rspErr = err
			rspMsg = fmt.Sprintf("failed to publish image sec msg")
			logging.Get().Err(err).Str("reqID", reqID).Str("msgID", req.RequestID).Msg("failed to publish image sec msg")
			return
		}
		if resp.Status != 0 {
			rspErr = fmt.Errorf("rsp status err.%v", resp.Status)
			rspMsg = fmt.Sprintf("rsp status.%v", resp.StatusMessage)
			logging.Get().Error().Str("status", resp.StatusMessage).Str("reqID", reqID).Str("msgID", req.RequestID).Msg("recv image sec msg response status err")
		} else {
			logging.Get().Info().Str("reqID", reqID).Str("msgID", req.RequestID).Msg("publish image sec msg ok")
		}
	}

	forwardMsgFunc(msg)
}

func (sh *StreamHandler) OnRead(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement image sec msg onRead")
}

func (sh *StreamHandler) OnUpdate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement image sec msg onUpdate")
}

func (sh *StreamHandler) OnDelete(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement image sec msg onDelete")
}

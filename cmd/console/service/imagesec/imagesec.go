package imagesec

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type StreamHandler struct {
	ServerStream rpcstream.MessageStream
}

func (sh *StreamHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	req := message.(*pb.ImageSecReq)
	msgID := req.MsgID
	logging.Get().Info().
		Str("reqID", reqID).
		Str("req", regLogStr(req)).
		Msg("recv image sec grpc msg")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(util.ImageSecGrpcTimeOut())*time.Second)
	defer cancel()
	resp, err := sh.ServerStream.PublishImageSecMsgByClusterKey(ctx, req.ClusterKey, req)
	if err != nil {
		resp = &pb.ImageSecResp{
			StatusMessage: err.Error(),
			Status:        1,
		}
	}
	sh.ReturnRpcResponse(s, reqID, msgID, resp)
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

func (sh *StreamHandler) ReturnRpcResponse(s rpcstream.Stream, reqID string, msgID string, resp *pb.ImageSecResp) {
	if resp == nil {
		resp = &pb.ImageSecResp{
			StatusMessage: "response is nil",
			Status:        1,
		}
	}
	logging.Get().Info().Str("reqID", reqID).Str("msgID", msgID).Str("resp", respLogStr(resp)).
		Msg("ReturnRpcResponse send imagesec response start")
	if err := s.SendResponse(reqID, resp); err != nil {
		logging.Get().Info().Str("reqID", reqID).Str("msgID", msgID).Str("resp", respLogStr(resp)).
			Msg("ReturnRpcResponse failed to send imagesec response")
		return
	}

	logging.Get().Info().Str("reqID", reqID).Str("msgID", msgID).Str("resp", respLogStr(resp)).
		Msg("ReturnRpcResponse send imagesec response success")
}

func regLogStr(req *pb.ImageSecReq) string {
	if req == nil {
		return fmt.Sprintf("rpc req is nil")
	}
	str := fmt.Sprintf("ClusterKey=%s,MsgID=%s,ImageSecReqType=%d,NodeName=%s",
		req.ClusterKey, req.MsgID, int32(req.ImageSecReqType), req.NodeName)
	return str
}

func respLogStr(resp *pb.ImageSecResp) string {
	if resp == nil {
		return fmt.Sprintf("rpc resp is nil")
	}
	str := fmt.Sprintf("StatusMessage=%s,Status=%d,BizMessage=%s,BizCode=%d",
		resp.StatusMessage, resp.Status, resp.BizMessage, resp.BizCode)
	return str
}

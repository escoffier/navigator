package service

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

type ImageSecHandler struct {
	ServerStream rpcstream.MessageStream
	ClusterKey   string
}

// 回包
func (i *ImageSecHandler) ReturnRpcResponse(s rpcstream.Stream, reqID string, msgID string, resp *pb.ImageSecResp) {
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
	str := fmt.Sprintf("ClusterKey=%s,RquestID=%s,ImageSecReqType=%d,NodeName=%s",
		req.ClusterKey, req.MsgID, int32(req.ImageSecReqType), req.NodeName)
	return str
}

func respLogStr(resp *pb.ImageSecResp) string {
	if resp == nil {
		return fmt.Sprintf("rpc resp is nil")
	}
	str := fmt.Sprintf("StatusMessage=%s,RquestID=%d,BizMessage=%s,BizCode=%d",
		resp.StatusMessage, resp.Status, resp.BizMessage, resp.BizCode)
	return str
}

// OnCreate 统一处理cluster manager grpc client接收的所有镜像安全相关信息,只做转发。
func (i *ImageSecHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	// parse pb msg
	req := message.(*pb.ImageSecReq)
	dstClusterKey := req.ClusterKey
	msgID := req.MsgID

	logging.Get().Info().
		Str("reqID", reqID).
		Str("req", regLogStr(req)).
		Msg("OnCreate recv image sec grpc msg")
	// check msg dst
	if dstClusterKey != i.ClusterKey {
		logging.Get().Error().Str("reqID", reqID).Str("msgID", msgID).Msg("image sec msg dst cluster wrong")
		resp := &pb.ImageSecResp{
			StatusMessage: "dst cluster wrong",
			Status:        1,
		}
		i.ReturnRpcResponse(s, reqID, msgID, resp)
		return
	}

	// publish func wrapper
	publishFunc := func(nodeKey string, msgType pb.MessageType, req *pb.ImageSecReq) (*pb.ImageSecResp, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(util.ImageSecGrpcTimeOut())*time.Second)
		defer cancel()
		resp, err := i.ServerStream.PublishImageSecMsgByNode(ctx, nodeKey, msgType, req)
		return resp, err
	}

	// forward msg to scanner
	if i.shouldPublishToScanner(req) {
		if req.ImageSecReqType == pb.ImageSecReqType_AviraDBUpdate ||
			req.ImageSecReqType == pb.ImageSecReqType_ClamavDBUpdate ||
			req.ImageSecReqType == pb.ImageSecReqType_TiDBUpdate {
			// 暂时不支持，前端已屏蔽这部分功能
			logging.Get().Error().Int32("msgType", int32(req.ImageSecReqType)).Msg("Rpc msgType not support")
		}

		resp, err := publishFunc(util.ScannerClusterManagerGrpcStreamKey(dstClusterKey), pb.MessageType_CREATE, req)
		if err != nil {
			resp = &pb.ImageSecResp{
				StatusMessage: err.Error(),
				Status:        1,
			}
		}
		i.ReturnRpcResponse(s, reqID, msgID, resp)
		return

	}

	if i.shouldPublishToDemon(req) {
		if req.NodeName == "" {
			resp := &pb.ImageSecResp{
				StatusMessage: "NodeClusterKey is empty",
				Status:        1,
			}
			i.ReturnRpcResponse(s, reqID, msgID, resp)
			return
		}
		// 不好的写法
		streamNodeKey := fmt.Sprintf("%s-node-image", req.NodeName)
		resp, err := publishFunc(streamNodeKey, pb.MessageType_CREATE, req)
		if err != nil {
			resp = &pb.ImageSecResp{
				StatusMessage: err.Error(),
				Status:        1,
				ErrNode:       []string{req.NodeName},
			}
		}
		i.ReturnRpcResponse(s, reqID, msgID, resp)
		return
	}
}

func (i *ImageSecHandler) shouldPublishToScanner(req *pb.ImageSecReq) bool {
	return req.ImageSecReqType == pb.ImageSecReqType_RegistryImageSync ||
		req.ImageSecReqType == pb.ImageSecReqType_RegistryHealthyCheck ||
		req.ImageSecReqType == pb.ImageSecReqType_RegistryImageScan
}

func (i *ImageSecHandler) shouldPublishToDemon(req *pb.ImageSecReq) bool {
	// 暂时就只有这几种
	if req.ImageSecReqType == pb.ImageSecReqType_NodeImageScan ||
		req.ImageSecReqType == pb.ImageSecReqType_SyncConfig ||
		req.ImageSecReqType == pb.ImageSecReqType_SyncResult {
		return true
	}
	return false
}

func (i *ImageSecHandler) OnRead(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("on-read not implement")
}

func (i *ImageSecHandler) OnUpdate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("on-update not implement")
}

func (i *ImageSecHandler) OnDelete(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("on-delete not implement")
}

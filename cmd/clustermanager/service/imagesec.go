package service

import (
	"context"
	"time"

	"github.com/hashicorp/go-multierror"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"fmt"

	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type ImageSecHandler struct {
	ServerStream rpcstream.MessageStream
	ClusterKey   string
}

// OnCreate 统一处理cluster manager grpc client接收的所有镜像安全相关信息,只做转发。
func (i *ImageSecHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	// parse pb msg
	req := message.(*pb.ImageSecReq)
	dstClusterKey := req.ClusterKey
	msgID := req.RequestID

	logging.Get().Info().
		Str("reqID", reqID).
		Str("msgID", msgID).
		Int32("msgType", int32(req.ImageSecReqType)).
		Str("dstClusterKey", req.ClusterKey).
		Str("curClusterKey", i.ClusterKey).
		Int("nodesCnt", len(req.NodeName)).
		Msg("recv image sec grpc msg")

	rspAndLogFunc := func(status int32, statusMsg string, errNodes []string) {
		orgRsp := pb.ImageSecResp{
			StatusMessage: statusMsg,
			Status:        status,
			ErrNode:       errNodes,
		}
		err := s.SendResponse(reqID, &orgRsp)
		if err != nil {
			logging.Get().Err(err).Str("reqID", reqID).Str("msgID", msgID).Msg("failed to send image sec msg rsp")
		}
	}

	// check msg dst
	if dstClusterKey != i.ClusterKey {
		logging.Get().Error().Str("reqID", reqID).Str("msgID", msgID).Msg("image sec msg dst cluster wrong")
		rspAndLogFunc(1, "recv wrong msg", nil)
		return
	}

	// publish func wrapper
	publishFunc := func(nodeKey string, msgType pb.MessageType, req *pb.ImageSecReq) (int32, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(util.ImageSecGrpcTimeOut())*time.Second)
		defer cancel()

		resp, err := i.ServerStream.PublishImageSecMsgByNode(ctx, nodeKey, msgType, req)
		if err != nil {
			return 1, err
		}
		if resp.Status != 0 {
			return resp.Status, fmt.Errorf("rsp err.%v", resp.StatusMessage)
		}
		return 0, nil
	}

	// forward msg to scanner
	if i.shouldPublishToScanner(req) {
		var err error
		var ret int32
		if req.ImageSecReqType == pb.ImageSecReqType_AviraDBUpdate ||
			req.ImageSecReqType == pb.ImageSecReqType_ClamavDBUpdate ||
			req.ImageSecReqType == pb.ImageSecReqType_TiDBUpdate {
			ret, err = publishFunc(util.ScannerClusterManagerGrpcStreamKey(dstClusterKey), pb.MessageType_UPDATE, req)
		} else {
			ret, err = publishFunc(util.ScannerClusterManagerGrpcStreamKey(dstClusterKey), pb.MessageType_CREATE, req)
		}
		if err != nil {
			logging.Get().Err(err).
				Str("reqID", reqID).
				Str("msgID", msgID).
				Int32("retCode", ret).
				Msg("failed to publish image sec msg to scanner")
			rspAndLogFunc(ret, err.Error(), nil)
		} else {
			logging.Get().Info().
				Str("reqID", reqID).
				Str("msgID", msgID).
				Msg("publish image sec msg to scanner ok")
			rspAndLogFunc(0, "ok", nil)
		}
		return
	}

	// publish msg to daemon
	var retCode int32
	var retErr error
	errNodes := make([]string, 0)
	if len(req.NodeName) > 0 {
		for _, v := range req.NodeName {
			streamNodeKey := fmt.Sprintf("%s-node-image", v)
			ret, err := publishFunc(streamNodeKey, pb.MessageType_CREATE, req)
			if err != nil {
				retCode = ret
				errNodes = append(errNodes, v)
				retErr = multierror.Append(retErr, err)
				logging.Get().Err(err).Str("node", v).Str("msgID", msgID).Msg("failed to push image sec msg to node")
				continue
			}
			logging.Get().Info().Str("node", v).Str("msgID", msgID).Msg("push image sec msg to node ok")
		}
	}
	if retErr != nil {
		rspAndLogFunc(retCode, retErr.Error(), errNodes)
	} else {
		rspAndLogFunc(0, "ok", nil)
	}
}

func (i *ImageSecHandler) shouldPublishToScanner(req *pb.ImageSecReq) bool {
	return req.ImageSecReqType == pb.ImageSecReqType_RegistryImageSync ||
		req.ImageSecReqType == pb.ImageSecReqType_RegistryHealthyCheck ||
		req.ImageSecReqType == pb.ImageSecReqType_RegistryImageScan
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

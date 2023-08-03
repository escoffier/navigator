package scapper

import (
	"context"
	"os"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/compliance"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type ProxyHandler struct {
	ServerStream rpcstream.MessageStream
}

func (sh *ProxyHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	req := message.(*pb.ComplianceScanReq)
	logging.Get().Info().Str("method", "OnCreate").
		Str("reqID", reqID).Str("msgID", req.RequestID).
		Msg("received console stream msg")

	var (
		resp *pb.CommonReponse
		err  error
	)

	defer func() {
		if err = s.SendResponse(reqID, resp); err != nil {
			logging.Get().Error().Err(err).Str("method", "OnCreate").
				Str("reqID", reqID).Str("msgID", req.RequestID).
				Msg("failed, send response to console")
		} else {
			logging.Get().Info().Str("method", "OnCreate").
				Str("reqID", reqID).Str("msgID", req.RequestID).
				Msg("success, send response to console")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err = sh.ServerStream.PushComplianceScan(ctx, req.NodeName+"-daemon", req)
	if err != nil {
		if resp == nil {
			resp = &pb.CommonReponse{
				Status:        1,
				StatusMessage: err.Error(),
			}
		}
		logging.Get().Err(err).Str("reqID", reqID).Str("msgID", req.RequestID).Msg("failed to publish image sec msg")
		return
	}
}

func (sh *ProxyHandler) OnRead(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement compliance proxy msg onRead")
}

func (sh *ProxyHandler) OnUpdate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement compliance proxy msg onUpdate")
}

func (sh *ProxyHandler) OnDelete(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement compliance proxy msg onDelete")
}

type ScanHandler struct {
	Writer mq.Writer
}

func (sh *ScanHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	req := message.(*pb.ComplianceScanReq)
	logging.Get().Info().Str("method", "OnCreate").
		Str("reqID", reqID).Str("msgID", req.RequestID).
		Str("checkType", req.CheckType).
		Str("MY_NODE_NAME", os.Getenv("MY_NODE_NAME")).
		Msg("received cluster-manager stream msg, start compliance scan")

	var (
		resp = &pb.CommonReponse{
			Status:        1,
			StatusMessage: "unknown error",
		}
		err error
	)
	defer func() {
		if err = s.SendResponse(reqID, resp); err != nil {
			logging.Get().Error().Err(err).Str("method", "OnCreate").
				Str("reqID", reqID).Str("msgID", req.RequestID).
				Msg("failed, send response to cluster-manager")
		} else {
			logging.Get().Info().Str("method", "OnCreate").
				Str("reqID", reqID).Str("msgID", req.RequestID).
				Msg("success, send response to cluster-manager")
		}
	}()

	nodeName := os.Getenv("MY_NODE_NAME")
	err = compliance.StartComplianceScan(model.ComplianceCheckType(req.CheckType), sh.Writer, req.RequestID, req.ClusterKey, nodeName, req.CheckIds, req.RuntimeName, req.RuntimeVersion)
	if err != nil {
		logging.Get().Error().Err(err).Str("method", "OnCreate").
			Str("reqID", reqID).Str("msgID", req.RequestID).
			Msg("compliance scan failed")
		resp.StatusMessage = err.Error()
		return
	}

	resp.Status = 0
	resp.StatusMessage = "success"
}

func (sh *ScanHandler) OnRead(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement compliance msg onRead")
}

func (sh *ScanHandler) OnUpdate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement compliance msg onUpdate")
}

func (sh *ScanHandler) OnDelete(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement compliance msg onDelete")
}

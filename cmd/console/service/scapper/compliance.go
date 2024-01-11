package scapper

import (
	"context"
	"os"
	"sync"
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

type NodeLoadProxyHandler struct {
	ServerStream rpcstream.MessageStream
}

func (n *NodeLoadProxyHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	req := message.(*pb.NodeLoadReq)
	logging.Get().Info().Str("obj", "NodeLoadProxyHandler-OnCreate").
		Str("reqID", reqID).Msg("received console stream msg")

	var (
		resp *pb.NodeLoadResp
		err  error
	)
	defer func() {
		if err = s.SendResponse(reqID, resp); err != nil {
			logging.Get().Error().Err(err).Str("obj", "NodeLoadProxyHandler-OnCreate").
				Str("reqID", reqID).Msg("failed, send response to console")
		} else {
			logging.Get().Info().Str("obj", "NodeLoadProxyHandler").Str("method", "OnCreate").
				Str("reqID", reqID).Msg("success, send response to console")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err = n.ServerStream.GetNodeLoadInfo(ctx, req.NodeName+"-daemon", req)
	if err != nil {
		if resp == nil {
			resp = &pb.NodeLoadResp{
				ErrMsg: err.Error(),
			}
		}
		logging.Get().Err(err).Str("obj", "NodeLoadProxyHandler-OnCreate").Str("reqID", reqID).Msg("failed to get  node load info.")
		return
	}
}

func (n *NodeLoadProxyHandler) OnRead(stream rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement NodeLoadProxyHandler msg OnRead")

}

func (n *NodeLoadProxyHandler) OnUpdate(stream rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement NodeLoadProxyHandler msg OnUpdate")

}

func (n *NodeLoadProxyHandler) OnDelete(stream rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement NodeLoadProxyHandler msg onDelete")

}

type ContainerMetricsProxyHandler struct {
	ServerStream rpcstream.MessageStream
}

func (n *ContainerMetricsProxyHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	req := message.(*pb.ContainerMetricsReq)
	logging.Get().Info().Str("obj", "NodeLoadProxyHandler-OnCreate").
		Str("reqID", reqID).Msg("received console stream msg")

	var (
		result = &pb.ContainerMetricsResp{}
	)
	defer func() {
		if err := s.SendResponse(reqID, result); err != nil {
			logging.Get().Error().Err(err).Str("obj", "ContainerMetricsProxyHandler-OnCreate").
				Str("reqID", reqID).Msg("failed, send response to console")
		} else {
			logging.Get().Info().Str("obj", "ContainerMetricsProxyHandler").Str("method", "OnCreate").
				Str("reqID", reqID).Msg("success, send response to console")
		}
	}()

	var wg sync.WaitGroup
	var lock sync.Mutex
	for _, nodeName := range req.NodeName {
		wg.Add(1)
		go func(nodeName string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			logging.Get().Info().Msgf("ContainerMetricsProxyHandler-OnCreate:nodeName:%s", nodeName)
			resp, err := n.ServerStream.GetContainerMetrics(ctx, nodeName+"-monitor", req)
			logging.Get().Err(err).Msgf("ContainerMetricsProxyHandler-OnCreate:nodeName:%s,err==nil:%v,resp:%s", nodeName, err == nil, resp.String())

			wg.Done()
			if err != nil {
				logging.Get().Err(err).Str("reqID", reqID).Msgf("ContainerMetricsProxyHandler-OnCreate: failed to get  container metrics. nodeName:%s,appLabel:%s", nodeName, req.AppLabel)
				return
			}
			lock.Lock()
			result.Metrics = append(result.Metrics, resp.Metrics...)
			lock.Unlock()
		}(nodeName)
	}
	wg.Wait()
}

func (n *ContainerMetricsProxyHandler) OnRead(stream rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement ContainerMetricsProxyHandler msg OnRead")

}

func (n *ContainerMetricsProxyHandler) OnUpdate(stream rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement ContainerMetricsProxyHandler msg OnUpdate")

}

func (n *ContainerMetricsProxyHandler) OnDelete(stream rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Error().Str("reqID", reqID).Msg("not implement ContainerMetricsProxyHandler msg onDelete")

}

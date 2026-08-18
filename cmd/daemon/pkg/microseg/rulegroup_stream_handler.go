package microseg

import (
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"

	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"

	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

// RuleGroupStreamHandler receives NetworkPolicyRuleGroupReq pushes (single
// create/update/delete events) from clustermanager and feeds them into
// RuleGroupController, replacing the k8s informer event handlers
// (addRuleGroup/updateRuleGroup/deleteRuleGroup) used when
// MICROSEG_GRPC_ENABLED is unset.
type RuleGroupStreamHandler struct {
	Controller *RuleGroupController
}

func (h *RuleGroupStreamHandler) upsert(message protoreflect.ProtoMessage) {
	req, ok := message.(*pb.NetworkPolicyRuleGroupReq)
	if !ok {
		logging.Get().Error().Msg("RuleGroupStreamHandler: unexpected message type")
		return
	}
	rg := payloadToRuleGroup(req.GetRuleGroup())
	h.Controller.streamCache.Set(rg)
	h.Controller.queue.Add(rg.Name)
}

func (h *RuleGroupStreamHandler) OnCreate(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	h.upsert(message)
}

func (h *RuleGroupStreamHandler) OnUpdate(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	h.upsert(message)
}

func (h *RuleGroupStreamHandler) OnDelete(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	req, ok := message.(*pb.NetworkPolicyRuleGroupReq)
	if !ok {
		logging.Get().Error().Msg("RuleGroupStreamHandler: unexpected message type on delete")
		return
	}
	name := req.GetRuleGroup().GetName()
	h.Controller.streamCache.Delete(name)
	h.Controller.queue.Add(name)
}

func (h *RuleGroupStreamHandler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
	logging.Get().Error().Msg("RuleGroupStreamHandler: OnRead not implemented")
}

// RuleGroupSyncStreamHandler receives the full-snapshot bootstrap push sent
// once clustermanager sees this daemon (re)connect (see Task 10's OnConnect
// registration), the gRPC-push equivalent of the initial List a k8s informer
// gets for free.
type RuleGroupSyncStreamHandler struct {
	Controller *RuleGroupController
}

func (h *RuleGroupSyncStreamHandler) OnCreate(_ rpcstream.Stream, _ string, message protoreflect.ProtoMessage) {
	req, ok := message.(*pb.NetworkPolicyRuleGroupSyncReq)
	if !ok {
		logging.Get().Error().Msg("RuleGroupSyncStreamHandler: unexpected message type")
		return
	}
	var rgs []*crdv1alpha1.NetworkPolicyRuleGroup
	for _, payload := range req.GetRuleGroups() {
		rgs = append(rgs, payloadToRuleGroup(payload))
	}
	removed := h.Controller.streamCache.ReplaceAll(rgs)
	for _, name := range removed {
		h.Controller.queue.Add(name)
	}
	for _, rg := range rgs {
		h.Controller.queue.Add(rg.Name)
	}
	h.Controller.synced.Store(true)
}

func (h *RuleGroupSyncStreamHandler) OnRead(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
}
func (h *RuleGroupSyncStreamHandler) OnUpdate(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
}
func (h *RuleGroupSyncStreamHandler) OnDelete(_ rpcstream.Stream, _ string, _ protoreflect.ProtoMessage) {
}

package rpcstream

import (
	"context"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type fakeStream struct {
	sent []*pb.ClusterMessage
}

func (f *fakeStream) Dispatch() error                          { return nil }
func (f *fakeStream) AddHandler(string, MessageHandler) error  { return nil }
func (f *fakeStream) AddHandlerFunc(string, ProcessFunc) error { return nil }
func (f *fakeStream) AddSession(id string, ack bool)           {}
func (f *fakeStream) DelSession(id string)                     {}
func (f *fakeStream) DelAllSession()                           {}
func (f *fakeStream) Send(m *pb.ClusterMessage) error {
	f.sent = append(f.sent, m)
	return nil
}
func (f *fakeStream) Response(ctx context.Context, reqUUID string) (protoreflect.ProtoMessage, error) {
	return nil, nil
}
func (f *fakeStream) SendResponse(string, protoreflect.ProtoMessage) error { return nil }
func (f *fakeStream) Run(stopChan chan struct{})                           {}
func (f *fakeStream) Dump() map[string]interface{}                         { return nil }
func (f *fakeStream) Clean()                                               {}

func Test_messageStream_PushRuleGroup(t *testing.T) {
	fs := &fakeStream{}
	s := &messageStream{streams: map[string]Stream{"node1-daemon": fs}}

	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "policy-node1"}}
	if err := s.PushRuleGroup(context.Background(), "node1-daemon", pb.MessageType_CREATE, req); err != nil {
		t.Fatalf("PushRuleGroup: %v", err)
	}
	if len(fs.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(fs.sent))
	}
	if fs.sent[0].MessageType != pb.MessageType_CREATE {
		t.Errorf("MessageType = %v, want CREATE", fs.sent[0].MessageType)
	}
	got, err := fs.sent[0].Payload.UnmarshalNew()
	if err != nil {
		t.Fatalf("UnmarshalNew: %v", err)
	}
	gotReq, ok := got.(*pb.NetworkPolicyRuleGroupReq)
	if !ok || gotReq.GetRuleGroup().GetName() != "policy-node1" {
		t.Errorf("payload = %+v, want RuleGroup.Name=policy-node1", got)
	}
}

func Test_messageStream_PushRuleGroup_UnknownNode(t *testing.T) {
	s := &messageStream{streams: map[string]Stream{}}
	req := &pb.NetworkPolicyRuleGroupReq{RuleGroup: &pb.NetworkPolicyRuleGroupPayload{Name: "policy-node1"}}
	if err := s.PushRuleGroup(context.Background(), "missing-daemon", pb.MessageType_CREATE, req); err == nil {
		t.Fatal("PushRuleGroup: want error for unknown node, got nil")
	}
}

func Test_messageStream_PushRuleGroupSync(t *testing.T) {
	fs := &fakeStream{}
	s := &messageStream{streams: map[string]Stream{"node1-daemon": fs}}

	req := &pb.NetworkPolicyRuleGroupSyncReq{RuleGroups: []*pb.NetworkPolicyRuleGroupPayload{{Name: "a"}, {Name: "b"}}}
	if err := s.PushRuleGroupSync(context.Background(), "node1-daemon", req); err != nil {
		t.Fatalf("PushRuleGroupSync: %v", err)
	}
	if len(fs.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(fs.sent))
	}
	got, err := fs.sent[0].Payload.UnmarshalNew()
	if err != nil {
		t.Fatalf("UnmarshalNew: %v", err)
	}
	gotReq, ok := got.(*pb.NetworkPolicyRuleGroupSyncReq)
	if !ok || len(gotReq.GetRuleGroups()) != 2 {
		t.Errorf("payload = %+v, want 2 rule groups", got)
	}
}

func Test_messageStream_ConnectedNodeKeys(t *testing.T) {
	s := &messageStream{streams: map[string]Stream{
		"node1-daemon": &fakeStream{},
		"node2-daemon": &fakeStream{},
	}}

	got := s.ConnectedNodeKeys()
	want := map[string]bool{"node1-daemon": true, "node2-daemon": true}
	if len(got) != len(want) {
		t.Fatalf("ConnectedNodeKeys() = %v, want keys %v", got, want)
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("unexpected key %q in ConnectedNodeKeys()", k)
		}
	}
}

func Test_messageStream_ConnectedNodeKeys_Empty(t *testing.T) {
	s := &messageStream{streams: map[string]Stream{}}
	if got := s.ConnectedNodeKeys(); len(got) != 0 {
		t.Fatalf("ConnectedNodeKeys() = %v, want empty", got)
	}
}

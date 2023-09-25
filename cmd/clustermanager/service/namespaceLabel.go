package service

import (
	"context"
	"k8s.io/client-go/kubernetes"
	"time"

	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NamespaceLabelHandler struct {
	KubeClient *kubernetes.Clientset
}

func (nl *NamespaceLabelHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*6)
	defer cancel()
	req := message.(*pb.NamespaceLabelSetReq)
	logging.Get().Debug().Msg(req.Name)
	resp := &pb.NamespaceLabelErrResp{}

	ns, err := nl.KubeClient.CoreV1().Namespaces().Get(ctx, req.Namespace, metav1.GetOptions{})
	if ns.Labels == nil {
		ns.Labels = make(map[string]string)
	}
	ns.Labels[req.Name] = req.Value

	_, err = nl.KubeClient.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		resp.ErrMsg = err.Error()
	}
	s.SendResponse(reqID, resp)
}

func (nl *NamespaceLabelHandler) OnRead(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {

}

func (nl *NamespaceLabelHandler) OnUpdate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {

}

func (nl *NamespaceLabelHandler) OnDelete(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*6)
	defer cancel()
	req := msg.(*pb.NamespaceLabelSetReq)
	logging.Get().Debug().Msg(req.Name)
	resp := &pb.NamespaceLabelErrResp{}

	ns, err := nl.KubeClient.CoreV1().Namespaces().Get(ctx, req.Namespace, metav1.GetOptions{})
	if ns.Labels != nil {
		delete(ns.Labels, req.Name)
	}
	_, err = nl.KubeClient.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		resp.ErrMsg = err.Error()
	}
	s.SendResponse(reqID, resp)
}

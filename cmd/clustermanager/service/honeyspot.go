package service

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
)

type HoneypotHandler struct {
	KubeClient *assets.Clientset
}

func (mf *HoneypotHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	req := message.(*pb.HoneySpotReq)
	logging.Get().Debug().Msg(req.Name)
	resp := &pb.HoneySpotResp{
		Name:          req.Name,
		Status:        0,
		StatusMessage: "create successfully",
	}
	servicePorts := make([]v1.ServicePort, 0, len(req.Ports))
	for _, p := range req.Ports {
		servicePorts = append(servicePorts, v1.ServicePort{
			Port:       p.Port,
			TargetPort: p.TargetPort,
		})
	}

	secrets := []v1.ImagePullSecret{
		{
			UserName: req.Secrets[0].UserName,
			Password: req.Secrets[0].Password,
			Server:   req.Secrets[0].Server,
		},
	}

	honeypot := &v1.Honeypot{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: req.Namespace,
			Name:      req.Name,
		},
		Spec: v1.HoneypotSpec{
			ClusterKey:  req.ClusterKey,
			WorkLoad:    req.WorkLoad,
			Ports:       servicePorts,
			Service:     req.Service,
			Image:       req.Image,
			Secrets:     secrets,
			Replica:     req.Replica,
			OutboundOff: req.OutboundOff,
		},
	}
	_, err := mf.KubeClient.TensorClientset.DefenseV1().Honeypots(req.Namespace).Create(ctx, honeypot, metav1.CreateOptions{})
	if err != nil {
		resp.Status = 1
		resp.StatusMessage = err.Error()
	}

	s.SendResponse(reqID, resp)
}

func (mf *HoneypotHandler) OnRead(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {

}

func (mf *HoneypotHandler) OnUpdate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {

}

func (mf *HoneypotHandler) OnDelete(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	req := msg.(*pb.HoneySpotReq)
	logging.Get().Debug().Msg(req.Name)
	resp := &pb.HoneySpotResp{
		Name:          req.Name,
		Status:        0,
		StatusMessage: "delete successfully",
	}
	err := mf.KubeClient.TensorClientset.DefenseV1().Honeypots(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		resp.Status = 1
		resp.StatusMessage = err.Error()
	}

	s.SendResponse(reqID, resp)
}

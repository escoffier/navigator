package service

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
)

type Service interface {
	MutatePodLabels(ctx context.Context, cluster string, review *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse
	MutateLabels(ctx context.Context, parameters *processors.MutatorParameters, pod *v1.Pod) []*processors.Patch
}

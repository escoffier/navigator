package processingcenter

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	service *Service
)

type MockPodService struct {
}

func (s *MockPodService) CheckPodExist(_ context.Context, _ *model.PodInfo) (bool, error) {
	return false, nil
}
func (s *MockPodService) IsolatePod(_ context.Context, pods []*model.PodInfo) (successfulPods, isolatedPods, deletedPods []*model.PodInfo) {
	return pods, nil, nil
}
func (s *MockPodService) CancelIsolatePod(_ context.Context, pods []*model.PodInfo) (successfulPods []*model.PodInfo) {
	return pods
}
func (s *MockPodService) DeletePods(_ context.Context, pods []*model.PodInfo) (successfulPods, notFoundPods []*model.PodInfo) {
	return pods, nil
}

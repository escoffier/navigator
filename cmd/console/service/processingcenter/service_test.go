package processingcenter

import (
	"context"
	"reflect"
	"testing"

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

func TestGenFullPodName(t *testing.T) {
	type args struct {
		object []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "test1",
			args:    args{object: []string{"/host-cluster@harbor-1-10@harbor-v1-sit-harbor-database-0"}},
			want:    "host-cluster/harbor-1-10/harbor-v1-sit-harbor-database-0",
			wantErr: false,
		},
		{
			name:    "test2",
			args:    args{object: []string{"/host-cluster@harbor-1-10@harbor-v1-sit-harbor-database-0", "test-cluster@namespace1@test111"}},
			want:    "host-cluster/harbor-1-10/harbor-v1-sit-harbor-database-0, test-cluster/namespace1/test111",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenFullPodName(tt.args.object)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenFullPodName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenFullPodName() got = %v, want %v", got, tt.want)
			}
		})
	}
}

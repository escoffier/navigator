package pull_image

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/pull-image"
	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/jobs/mock-pull-image"
	"testing"
)

func TestPullImage(t *testing.T) {
	component.DumpJobs()

	config := jobs.JobConfig{
		Type: "mock-pull-image",
	}
	mockPullImage, err := jobs.Open(config)
	if err != nil {
		t.Fatalf("not find job mock-pull-image:%v", err)
	}
	component.DumpJobs()

	result, err := mockPullImage.Run(context.Background(), jobs.Param{})
	if err != nil {
		t.Fatalf("run err:%v", err)
	}
	t.Logf("result:%v", result)
}

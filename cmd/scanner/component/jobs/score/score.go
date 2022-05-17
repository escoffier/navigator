package score

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	JobName = "image-score"
)

type ImageScore struct {
}

func (i *ImageScore) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	// get scan result from param

	// calculate score

	// return score
	result := make(jobs.Artifact)
	result["image-score"] = ""

	return result, nil
}

func init() {
	err := jobs.Register(JobName, newJob)
	if err != nil {
		logging.GetLogger().Err(err).Str("jobName", JobName).Msg("int job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	i := &ImageScore{}

	return i, nil
}

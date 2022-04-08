package internal

import (
	"unicode/utf8"

	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
)

func VerifyPolicy(policy *scap.Policy) error {
	if len(policy.Name) == 0 {
		return errors.New("policy name is required")
	}

	if utf8.RuneCountInString(policy.Name) > 100 {
		return errors.New("policy name is too long")
	}

	if utf8.RuneCountInString(policy.Comment) > 250 {
		return errors.New("policy description is too long")
	}

	if len(policy.RuleIds) == 0 {
		return errors.New("policy must have at least one rule")
	}

	return nil
}

func VerifyJob(job *scap.Job) error {
	if job.PolicyID == 0 {
		return errors.New("policy id is required")
	}

	if len(job.ClusterInfos) == 0 {
		return errors.New("cluster info is required")
	}

	for i := range job.ClusterInfos {
		if len(job.ClusterInfos[i].ClusterKey) == 0 {
			return errors.New("cluster key is required")
		}

		if !job.ClusterInfos[i].IsAllNodes && len(job.ClusterInfos[i].Nodes) == 0 {
			return errors.New("node ids are required")
		}
	}

	return nil
}

func VerifyCronJob(job *scap.CronJob) error {
	if err := VerifyJob(&job.Job); err != nil {
		return err
	}

	if job.Cron == nil {
		return errors.New("cron is required")
	}

	return nil
}

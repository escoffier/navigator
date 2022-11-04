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

func VerifyCronJob(job *scap.CronJob) error {
	if err := job.Job.VerifyJob(); err != nil {
		return err
	}

	if job.Cron == nil {
		return errors.New("cron is required")
	}

	return nil
}

package vulnmatch

import (
	"context"
	"fmt"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/commands/artifact"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"
)

type Matcher struct {
	option artifact.Option
	runner Runner
	res    report.Report
}

func (m *Matcher) MatchVulnerability(artifactDetail ftypes.ArtifactDetail) error {
	rp, err := m.runner.ScanFilesystem(context.Background(), m.option, artifactDetail)
	if err != nil {
		logging.Get().Err(err).Msg("scan vulnerability filed")
		return err
	}

	// fill vulnerability detail
	resultClient := initializeResultClient()
	results := rp.Results
	for i := range results {
		resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
	}

	m.res = rp
	logging.Get().Trace().Interface("vulns", m.res).Msg("match result")

	return nil
}

func (m *Matcher) Option() artifact.Option {
	return m.option
}

func (m *Matcher) Results() report.Results {
	return m.res.Results
}

func (m *Matcher) DumpResult(outfile string) error {
	output, err := os.Create(outfile)
	if err != nil {
		logging.Get().Err(err).Msg("create output file failed.")
		return err
	}
	defer func() {
		_ = output.Close()
	}()

	m.option.ReportOption.Output = output

	rp, err := filter(context.Background(), m.option, m.res)
	if err != nil {
		logging.Get().Err(err).Msg("filter err")
		return fmt.Errorf("filter err:%v", err)
	}

	if err = report.Write(rp, report.Option{
		AppVersion:         m.option.GlobalOption.AppVersion,
		Format:             m.option.Format,
		Output:             m.option.Output,
		Severities:         m.option.Severities,
		OutputTemplate:     m.option.Template,
		IncludeNonFailures: m.option.IncludeNonFailures,
		Trace:              m.option.Trace,
	}); err != nil {
		return fmt.Errorf("unable to write results:%v", err)
	}
	return nil
}

func NewMatcher() (*Matcher, error) {
	m := &Matcher{}
	opt := InitOption()
	m.option = opt

	r, err := NewRunner(opt)
	if err != nil {
		logging.Get().Err(err).Msg("create matcher failed")
		return nil, err
	}
	m.runner = r

	return m, nil
}

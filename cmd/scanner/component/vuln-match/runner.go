package vulnmatch

import (
	"context"
	"errors"
	"fmt"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/cache"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/commands/artifact"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/commands/operation"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/detector/ospkg"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/result"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/utils"
)

var (
	SkipScan = errors.New("skip subsequent processes")
)

type Runner interface {
	// ScanFilesystem scans a filesystem
	ScanFilesystem(ctx context.Context, opt artifact.Option, artifactDetail ftypes.ArtifactDetail) (report.Report, error)
	// Report writes a report
	Report(opt artifact.Option, report report.Report) error
}

type runner struct {
	cache  cache.Cache
	dbOpen bool
}

type runnerOption func(*runner)

//var (
//	dbInitOnce sync.Once
//)

func NewRunner(cliOption artifact.Option, opts ...runnerOption) (Runner, error) {
	r := &runner{}
	for _, opt := range opts {
		opt(r)
	}

	var err error

	// reserve this log for debug trivy
	err = log.InitLogger(cliOption.Debug, cliOption.Quiet)
	if err != nil {
		return nil, fmt.Errorf("logger error: %v", err)
	}

	// scanner will init db
	//dbInitOnce.Do(func() {
	//	if err = r.initDB(cliOption); err != nil {
	//		logging.Get().Err(err).Msg("init vuln db err")
	//	}
	//})

	return r, err
}

func (r *runner) ScanFilesystem(ctx context.Context, opt artifact.Option, artifactDetail ftypes.ArtifactDetail) (report.Report, error) {
	logging.Get().Debug().Interface("opt", opt).Msg("start match vuln")

	// Disable the individual package scanning
	//opt.DisabledAnalyzers = append(opt.DisabledAnalyzers, analyzer.TypeIndividualPkgs...)

	// detect vuln
	target := " " // only use in report
	detector := ospkg.Detector{}
	scanner := NewScanner(nil, detector)

	scanOptions := types.ScanOptions{
		VulnType:            opt.VulnType,
		SecurityChecks:      opt.SecurityChecks,
		ScanRemovedPackages: opt.ScanRemovedPkgs, // this is valid only for 'image' subcommand
		ListAllPackages:     opt.ListAllPkgs,
	}
	vulns, os, err := scanner.Scan(context.Background(), target, artifactDetail, scanOptions)
	if err != nil {
		log.Fatal(fmt.Errorf("scan err:%v", err))
		return report.Report{}, err
	}

	//logging.Get().Debug().Msgf("os:%+v", *os)
	//logging.Get().Debugf("vulns:%+v", vulns)
	//logging.Get().Debug().Msgf("vulns num:%+v", len(vulns[0].Vulnerabilities))

	return report.Report{
		SchemaVersion: report.SchemaVersion,
		Metadata: report.Metadata{
			OS: os,
		},
		Results: vulns,
	}, nil
}

func (r *runner) initCache(c artifact.Option) error {
	// Skip initializing cache when custom cache is passed
	if r.cache != nil {
		return nil
	}

	// standalone mode
	utils.SetCacheDir(c.CacheDir)
	tmpCache, err := operation.NewCache(c.CacheOption)
	if err != nil {
		return fmt.Errorf("unable to initialize the cache: %w", err)
	}
	logging.Get().Debug().Msgf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		defer func() { _ = tmpCache.Close() }()
		if err = tmpCache.Reset(); err != nil {
			return fmt.Errorf("cache reset error: %w", err)
		}
		return SkipScan
	}
	if c.ClearCache {
		defer func() { _ = tmpCache.Close() }()
		if err = tmpCache.ClearArtifacts(); err != nil {
			return fmt.Errorf("cache clear error: %w", err)
		}
		return SkipScan
	}

	r.cache = tmpCache
	return nil
}

func (r *runner) initDB(c artifact.Option) error {
	logging.Get().Debug().Msg("init db")

	if !r.dbOpen {
		logging.Get().Debug().Msgf("ready to open db:%s", c.CacheDir)
		if err := db.Init(c.CacheDir); err != nil {
			return fmt.Errorf("error in vulnerability DB initialize: %w", err)
		}
		r.dbOpen = true
	} else {
		logging.Get().Debug().Msg("db already opened")
	}

	return nil
}

func (r *runner) Report(opt artifact.Option, rp report.Report) error {
	if err := report.Write(rp, report.Option{
		AppVersion:         opt.GlobalOption.AppVersion,
		Format:             opt.Format,
		Output:             opt.Output,
		Severities:         opt.Severities,
		OutputTemplate:     opt.Template,
		IncludeNonFailures: opt.IncludeNonFailures,
		Trace:              opt.Trace,
	}); err != nil {
		return fmt.Errorf("unable to write results: %w", err)
	}

	return nil
}

func filter(ctx context.Context, opt artifact.Option, rp report.Report) (report.Report, error) {
	resultClient := initializeResultClient()
	results := rp.Results
	for i := range results {
		resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
		vulns, misconfSummary, misconfs, err := resultClient.Filter(ctx, results[i].Vulnerabilities, results[i].Misconfigurations,
			opt.Severities, opt.IgnoreUnfixed, opt.IncludeNonFailures, opt.IgnoreFile, opt.IgnorePolicy)
		if err != nil {
			return report.Report{}, fmt.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
		results[i].Misconfigurations = misconfs
		results[i].MisconfSummary = misconfSummary
	}
	return rp, nil
}

func initializeResultClient() result.Client {
	dbConfig := db.Config{}
	client := result.NewClient(dbConfig)
	return client
}

// UpdateDB for test, should not use in prod
func UpdateDB(c artifact.Option) error {
	// download the database file
	//noProgress := c.Quiet || c.NoProgress
	if err := operation.DownloadDB(c.AppVersion, c.CacheDir, false, c.SkipDBUpdate); err != nil {
		return err
	}

	return nil
}

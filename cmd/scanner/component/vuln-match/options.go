package vulnmatch

import (
	dbTypes "scm.tensorsecurity.cn/tensorsecurity-rd/trivy-db/pkg/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/commands/artifact"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/commands/option"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/utils"
	"strings"
)

const (
	Severities       = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
	DefaultCachePath = "/root/alldb/node"
)

type MatcherOption func(m *Matcher)

func InitOption() artifact.Option {
	// init report display severity
	s := splitSeverity(Severities)

	opt := artifact.Option{
		GlobalOption: option.GlobalOption{
			AppVersion: "dev",
			Quiet:      false,
			Debug:      true,
			CacheDir:   utils.DefaultCacheDir(),
		},
		ArtifactOption: option.ArtifactOption{
			OfflineScan: true,
		},
		ReportOption: option.ReportOption{
			SecurityChecks: []string{types.SecurityCheckVulnerability},
			VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
			Format:         "table", // default output
			Severities:     s,
		},
		DBOption: option.DBOption{
			SkipDBUpdate: false,
		},
		ImageOption: option.ImageOption{
			ListAllPkgs: true,
		},
	}
	return opt
}

func splitSeverity(severity string) []dbTypes.Severity {
	var severities []dbTypes.Severity
	for _, s := range strings.Split(severity, ",") {
		severity, err := dbTypes.NewSeverity(s)
		if err != nil {
			log.Logger.Warnf("unknown severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	return severities
}

func WithCachePath(cachePath string) MatcherOption {
	return func(m *Matcher) {
		if len(cachePath) > 0 {
			m.option.CacheDir = cachePath
		}
	}
}

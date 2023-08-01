package vulnmatch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/detector/library"
	ospkgDetector "scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/detector/ospkg"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/scanner/local"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"
)

var (
	pkgTargets = map[string]string{
		ftypes.PythonPkg: "Python",
		ftypes.GemSpec:   "Ruby",
		ftypes.NodePkg:   "Node.js",
		ftypes.Jar:       "Java",
	}
)

// Scanner implements the OspkgDetector and LibraryDetector
type Scanner struct {
	applier       local.Applier
	ospkgDetector local.OspkgDetector
}

// NewScanner is the factory method for Scanner
func NewScanner(applier local.Applier, ospkgDetector local.OspkgDetector) Scanner {
	return Scanner{
		applier:       applier,
		ospkgDetector: ospkgDetector,
	}
}

func (s Scanner) Scan(ctx context.Context, target string, artifactDetail ftypes.ArtifactDetail, options types.ScanOptions) (report.Results, *ftypes.OS, error) {
	var eosl bool
	var results report.Results
	var vulnResults report.Results

	vulnResults, eosl, err := s.checkVulnerabilities(target, artifactDetail, options)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect vulnerabilities: %w", err)
	}
	if artifactDetail.OS != nil {
		artifactDetail.OS.Eosl = eosl
	}
	results = append(results, vulnResults...)

	return results, artifactDetail.OS, nil
}

func (s Scanner) checkVulnerabilities(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
	report.Results, bool, error) {
	var eosl bool
	var results report.Results

	if StringInSlice(types.VulnTypeOS, options.VulnType) {
		log.Logger.Debugf("scan vuln os")
		result, detectedEosl, err := s.scanOSPkgs(target, detail, options)
		if err != nil {
			return nil, false, fmt.Errorf("unable to scan OS packages: %w", err)
		} else if result != nil {
			results = append(results, *result)
		}
		eosl = detectedEosl
	}

	if StringInSlice(types.VulnTypeLibrary, options.VulnType) {
		libResults, err := s.scanLibrary(detail.Applications, options)
		if err != nil {
			return nil, false, fmt.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, libResults...)
	}

	return results, eosl, nil
}

func (s Scanner) scanOSPkgs(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
	*report.Result, bool, error) {
	if detail.OS == nil {
		log.Logger.Debug("Detected OS: unknown")
		return nil, false, nil
	}
	log.Logger.Infof("Detected OS: %s", detail.OS.Family)

	pkgs := detail.Packages
	if options.ScanRemovedPackages {
		pkgs = mergePkgs(pkgs, detail.HistoryPackages)
	}

	result, eosl, err := s.detectVulnsInOSPkgs(target, detail.OS.Family, detail.OS.Name, pkgs)
	if err != nil {
		return nil, false, fmt.Errorf("failed to scan OS packages: %w", err)
	} else if result == nil {
		return nil, eosl, nil
	}

	if options.ListAllPackages {
		sort.Slice(pkgs, func(i, j int) bool {
			return strings.Compare(pkgs[i].Name, pkgs[j].Name) <= 0
		})
		result.Packages = pkgs
	}

	return result, eosl, nil
}

func (s Scanner) detectVulnsInOSPkgs(target, osFamily, osName string, pkgs []ftypes.Package) (*report.Result, bool, error) {
	if osFamily == "" {
		return nil, false, nil
	}
	vulns, eosl, err := s.ospkgDetector.Detect("", osFamily, osName, time.Time{}, pkgs)
	if err == ospkgDetector.ErrUnsupportedOS {
		return nil, false, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	artifactDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osName)
	result := &report.Result{
		Target:          artifactDetail,
		Vulnerabilities: vulns,
		Class:           report.ClassOSPkg,
		Type:            osFamily,
	}
	return result, eosl, nil
}

func (s Scanner) scanLibrary(apps []ftypes.Application, options types.ScanOptions) (report.Results, error) {
	log.Logger.Infof("Number of language-specific files: %d", len(apps))
	if len(apps) == 0 {
		return nil, nil
	}

	var results report.Results
	printedTypes := map[string]struct{}{}
	for _, app := range apps {
		if len(app.Libraries) == 0 {
			continue
		}

		// Prevent the same log messages from being displayed many times for the same type.
		if _, ok := printedTypes[app.Type]; !ok {
			log.Logger.Infof("Detecting %s vulnerabilities...", app.Type)
			printedTypes[app.Type] = struct{}{}
		}

		log.Logger.Debugf("Detecting library vulnerabilities, type: %s, path: %s", app.Type, app.FilePath)
		vulns, err := library.Detect(app.Type, app.Libraries)
		if err != nil {
			return nil, fmt.Errorf("failed vulnerability detection of libraries: %w", err)
		}

		target := app.FilePath
		if t, ok := pkgTargets[app.Type]; ok && target == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			target = t
		}

		libReport := report.Result{
			Target:          target,
			Vulnerabilities: vulns,
			Class:           report.ClassLangPkg,
			Type:            app.Type,
		}
		if options.ListAllPackages {
			libReport.Packages = app.Libraries
		}
		results = append(results, libReport)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}

func mergePkgs(pkgs, pkgsFromCommands []ftypes.Package) []ftypes.Package {
	// pkg has priority over pkgsFromCommands
	uniqPkgs := map[string]struct{}{}
	for _, pkg := range pkgs {
		uniqPkgs[pkg.Name] = struct{}{}
	}
	for _, pkg := range pkgsFromCommands {
		if _, ok := uniqPkgs[pkg.Name]; ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// StringInSlice checks if strings exist in list of strings
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

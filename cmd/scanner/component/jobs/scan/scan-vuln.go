package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	executorScanVulnName = "scan-vuln"
)

type ExecutorScanVuln struct {
	imageCacheURL string
	policy        interface{}
}

func (e *ExecutorScanVuln) filterCustomPkg(r *report.Report, customPkg []task.CustomPkgPolicy, customLicenses []string) []model.Software {
	logging.GetLogger().Info().Interface("customPkg", customPkg).Msg("filterCustomPkg")
	abnormalPkg := make(map[string]bool)
	abnormalLicense := make(map[string]bool)
	for _, v := range customPkg {
		pkg := fmt.Sprintf("%s/%s", v.CustomPkgName, v.CustomPkgVersion)
		abnormalPkg[pkg] = true
	}
	for i := range customLicenses {
		abnormalLicense[customLicenses[i]] = true
	}
	logging.GetLogger().Info().Int("Results", len(r.Results)).Msg("imageScanSoftware")
	res := make([]model.Software, 0)
	for i := range r.Results {
		logging.GetLogger().Info().Int("Packages", len(r.Results[i].Packages)).Msg("imageScanSoftware")
		for j := range r.Results[i].Packages {
			vv := r.Results[i].Packages[j]

			pkg := model.Software{
				Name:            vv.Name,    // fixme(liuqiang) use vv.Name OR vv.SrcName
				Version:         vv.Version, // fixme(liuqiang) use vv.Version OR vv.SrcVersion
				License:         vv.License,
				AbnormalSoft:    false,
				AbnormalLicense: false,
				LayerDigest:     vv.Layer.Digest,
			}
			pkgKey := fmt.Sprintf("%s/%s", pkg.Name, pkg.Version)
			if abnormalPkg[pkgKey] {
				pkg.AbnormalSoft = true
			}
			if pkg.License != "" && abnormalLicense[pkg.License] {
				pkg.AbnormalLicense = true
			}
			res = append(res, pkg)
		}
	}

	for i := range r.Results {
		logging.GetLogger().Info().Int("Packages", len(r.Results[i].Packages)).Msg("imageScanSoftware")
		for j := range r.Results[i].Vulnerabilities {
			vv := r.Results[i].Vulnerabilities[j]

			pkg := model.Software{
				Name:            vv.PkgName,
				Version:         vv.InstalledVersion,
				AbnormalSoft:    false,
				AbnormalLicense: false,
				LayerDigest:     vv.Layer.Digest,
			}
			pkgKey := fmt.Sprintf("%s/%s", pkg.Name, pkg.Version)
			if abnormalPkg[pkgKey] {
				pkg.AbnormalSoft = true
			}
			if pkg.License != "" && abnormalLicense[pkg.License] {
				pkg.AbnormalLicense = true
			}
			res = append(res, pkg)
		}
	}

	return res
}

func (e *ExecutorScanVuln) Scan(ctx context.Context, param Param) (Artifact, error) {
	// get image cache url
	u, ok := param["imageCacheUrl"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'imageCacheUrl' in parameter")
		return nil, errors.New("miss 'imageCacheUrl' in parameter")
	}
	e.imageCacheURL = u
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(e.imageCacheURL, nameOpts...)
	if err != nil {
		logging.GetLogger().Err(err).Msg("parse image failed")
		return nil, errors.New("parse image failed")
	}

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()
	newImage := "0.0.0.0:5566/" + repositoryName + ":" + tag
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		Image, ok := param["dockerImage"].(string)
		if ok {
			newImage = Image
		}
	}
	// scan
	if component.TrivyService == nil {
		logging.GetLogger().Error().Msg("TrivyService didn't start")
		return nil, errors.New("TrivyService didn't start")
	}

	result, err := component.TrivyService.Scan(ctx, newImage)
	if err != nil {
		logging.GetLogger().Err(err).Msg("Scan image failed")
		return nil, errors.New("scan image failed")
	}
	r := make(map[string]interface{})

	policyRule, ok := e.policy.(task.VulnPolicy)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'VulnPolicyRule' in parameter")
		return nil, errors.New("miss 'VulnPolicyRule' in parameter")
	}
	customPkg := make([]task.CustomPkgPolicy, 0)
	customLicenses := make([]string, 0)
	if policyRule.Pkgs != "" {
		if err := json.Unmarshal([]byte(policyRule.Pkgs), &customPkg); err != nil {
			logging.GetLogger().Err(err).Msg("Unmarshal VulnPolicyRule failed")
		}
	}
	if policyRule.Licenses != "" {
		if err := json.Unmarshal([]byte(policyRule.Licenses), &customLicenses); err != nil {
			logging.GetLogger().Err(err).Msg("Unmarshal VulnPolicyRule failed")
		}
	}

	r["result"] = result
	r["customFlag"] = 1
	r["software"] = e.filterCustomPkg(result, customPkg, customLicenses)

	return r, nil
}

func init() {
	err := Register(executorScanVulnName, newScanVuln)
	if err != nil {
		logging.GetLogger().Err(err).Str("executorName", executorScanVulnName).Msg("int executor err")
	}
}

func newScanVuln(config ExecutorConfig) (Executor, error) { // Open时调用
	e := &ExecutorScanVuln{}
	e.policy = config.Policy
	return e, nil
}

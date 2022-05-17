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

func (e *ExecutorScanVuln) fileterCustomPkg(r *report.Report, customPkg []task.SingleVulnPolicy) []model.Software {
	mp := make(map[string]int)
	for _, v := range customPkg {
		unikey := fmt.Sprintf("%v/%v", v.CustomPackageName, v.CustomPackageVersion)
		mp[unikey] = 1
	}
	var res []model.Software
	// res := &report.Report{}
	// res.ArtifactName = r.ArtifactName
	// res.SchemaVersion = r.SchemaVersion
	// res.ArtifactType = r.ArtifactType
	// res.Metadata = r.Metadata
	for _, v := range r.Results {
		singleResult := report.Result{}
		singleResult.Target = v.Target
		singleResult.Type = v.Type
		singleResult.Class = v.Class
		singleResult.MisconfSummary = v.MisconfSummary
		singleResult.Misconfigurations = v.Misconfigurations
		singleResult.Packages = v.Packages
		for _, vv := range v.Vulnerabilities {
			unikey := fmt.Sprintf("%v/%v", vv.PkgName, vv.InstalledVersion)
			flag, ok := mp[unikey]
			if ok && flag == 1 {
				res = append(res, model.Software{Name: vv.PkgName, Version: vv.InstalledVersion})
				mp[unikey] = 0
			}
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
	// repo := ref.Context()

	// registryStr := repo.RegistryStr()

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()
	Newimage := "0.0.0.0:5566/" + repositoryName + ":" + tag
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		Image, ok := param["dockerImage"].(string)
		if ok {
			Newimage = Image
		}
	}
	// scan
	if component.TrivyService == nil {
		logging.GetLogger().Error().Msg("TrivyService didn't start")
		return nil, errors.New("TrivyService didn't start")
	}

	result, err := component.TrivyService.Scan(ctx, Newimage)
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
	var customPkg []task.SingleVulnPolicy
	if len(policyRule.Pkgs) > 0 {
		err = json.Unmarshal([]byte(policyRule.Pkgs), &customPkg)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Unmarshal VulnPolicyRule failed")
			return nil, errors.New("Unmarshal VulnPolicyRule failed")
		}
	}

	r["result"] = result
	r["customFlag"] = 1
	r["software"] = e.fileterCustomPkg(result, customPkg)

	// logging.GetLogger().Info().Msgf("result is : %v", result.Results)
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

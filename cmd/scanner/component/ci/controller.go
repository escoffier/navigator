package ci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	vulnmatch "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-match"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Controller struct {
	policy  *scanner_ci.CiPolicy
	matcher *vulnmatch.Matcher
	dal     adaptStore.ScanCiInterface
}

func (c *Controller) HandleTiDb(orgVersion string) ([]byte, error) {
	return nil, nil
}

func (c *Controller) GetPolicyByName(name string) (*scanner_ci.Policy, error) {
	// todo: select policy from db
	logging.Get().Debug().Str("name", name).Msg("get policy")

	// test
	tmpPolicy := &scanner_ci.Policy{
		Vuln: scanner_ci.VulnRule{
			Enabled:        true,
			Severity:       model.SeverityMedium,
			BlackListVulns: []string{"CVE-2019-17594"},
			Action:         scanner_ci.CiActionBlock,
		},
	}

	return tmpPolicy, nil
}

func (c *Controller) VulnerabilityMatch(artifact scanner_ci.ImageArtifact) (report.Results, error) {
	logging.Get().Debug().
		Str("image", artifact.ImageName).
		Str("uuid", artifact.UUID).
		Msg("match vuln with image artifact")

	res, err := c.matcher.MatchVulnerability(artifact.Artifact)
	if err != nil {
		logging.Get().Err(err).
			Str("image", artifact.ImageName).
			Str("uuid", artifact.UUID).
			Msg("analyze vuln failed")
		return report.Results{}, err
	}

	return res, nil
}

func (c *Controller) SaveResult(result scanner_ci.PolicyResult) error {
	ctx := context.Background()
	scanDetails := model.ScanDetailScanImage{}
	c.arrangeVulnDetails(&result.Vulnerabilities.Results, &scanDetails)
	imageID, err := c.logPostgresRecord(ctx, result, &scanDetails)
	if err != nil {
		logging.Get().Err(err).Msgf("log Ci Record error")
		return err
	}

	err = c.logPostgresSensitive(ctx, result, imageID)
	if err != nil {
		logging.Get().Err(err).Msgf("log Ci sensitive error")
	}

	err = c.logPostgresVuln(ctx, result, &scanDetails, imageID)
	if err != nil {
		logging.Get().Err(err).Msgf("log Ci Vuln error")
	}

	err = c.logPostgresPkgs(ctx, result, imageID)
	if err != nil {
		logging.Get().Err(err).Msgf("log Ci Pkg error")
	}

	err = c.logPostgresPkgImages(ctx, result, &scanDetails, imageID)
	if err != nil {
		logging.Get().Err(err).Msgf("log Ci PkgImages error")
	}
	logging.Get().Debug().Str("image", result.Artifact.ImageName).Msg("save ci result ok")
	return nil
}

func (c *Controller) logPostgresRecord(ctx context.Context, result scanner_ci.PolicyResult, scanDetails *model.ScanDetailScanImage) (int64, error) {
	policyBytes, err := json.Marshal(result.PolicySnapShot)
	if err != nil {
		logging.Get().Err(err).Msgf("Marshal PolicySnapShot error")
	}

	histogormBytes, err := json.Marshal(scanDetails.SeverityHistogram)
	if err != nil {
		logging.Get().Err(err).Msgf("Marshal SeverityHistogram error")
	}
	layersBytes, err := json.Marshal(result.Artifact.ImageLayers)
	if err != nil {
		logging.Get().Err(err).Msgf("Marshal ImageLayers error")
	}

	var flag uint64
	for _, v := range scanDetails.VulnDetails {
		if len(v.Vulns) > 0 {
			flag |= 1 << (scanner_ci.VulnQuestion - 1)
			break
		}
	}
	if len(result.MatchSensitiveFiles.Files) > 0 {
		flag |= 1 << (scanner_ci.SenSitiveQuestion - 1)
	}
	if len(result.MatchSensitiveFiles.DefaultFiles) > 0 {
		flag |= 1 << (scanner_ci.SenSitiveQuestion - 1)
	}
	remediation := scanner_ci.ImageRemediation{Vuln: result.MatchVulns.Remediation, Sensitive: result.MatchSensitiveFiles.Remediation}
	remediationBytes, err := json.Marshal(remediation)
	if err != nil {
		logging.Get().Err(err).Msgf("get remedation error")
	}

	record := scanner_ci.CiScan{
		ImageName:             result.Artifact.ImageName,
		UniqueImage:           util.GenerateUUID64(result.Artifact.ImageName),
		PipelineName:          result.PipelineName,
		PolicySnapshot:        policyBytes,
		Mode:                  result.PolicyResultCode,
		SeverityHistogramJSON: histogormBytes,
		Flag:                  flag,
		Message:               result.ExistMsg,
		MatchWhitelist:        result.MatchImageWhiteListResult.Match,
		Remediation:           remediationBytes,
		Layers:                layersBytes,
		StartedAt:             time.Now().UnixMilli(),
		FinishAt:              time.Now(),
	}

	if result.Artifact.Artifact.OS != nil {
		record.OS = result.Artifact.Artifact.OS.Family + ":" + result.Artifact.Artifact.OS.Name
	} else {
		record.OS = "unknown"
	}

	id, err := c.dal.CreateRecord(ctx, record)
	if err != nil {
		return -1, err
	}
	return id, nil
}

func (c *Controller) logPostgresSensitive(ctx context.Context, result scanner_ci.PolicyResult, ImageId int64) error {
	sensitives := []scanner_ci.CiSensitiveImages{}
	mp := make(map[string]struct{})
	flag := result.PolicySnapShot.SensitiveFile.Enabled

	for _, v := range result.MatchSensitiveFiles.Files {
		if _, ok := mp[v]; !ok {
			mp[v] = struct{}{}
			sensitives = append(sensitives, scanner_ci.CiSensitiveImages{ImageID: ImageId, MatchPolicy: flag, File: v})
		}
	}

	for _, v := range result.MatchSensitiveFiles.DefaultFiles {
		if _, ok := mp[v]; !ok {
			mp[v] = struct{}{}
			sensitives = append(sensitives, scanner_ci.CiSensitiveImages{ImageID: ImageId, MatchPolicy: false, File: v})
		}
	}
	err := c.dal.CreateSensitiveImages(ctx, sensitives)
	if err != nil {
		logging.Get().Err(err).Msgf("create sensitive file error")
		return err
	}
	return nil
}

func (c *Controller) logPostgresPkgs(ctx context.Context, result scanner_ci.PolicyResult, ImageID int64) error {
	logging.Get().Debug().
		Int("osPkgNum", len(result.Artifact.Artifact.Packages)).
		Int("appNum", len(result.Artifact.Artifact.Applications)).
		Msg("compose ci pkgs")

	addPkgFunc := func(found []types.Package, result []scanner_ci.CiPkgs, filter map[string]struct{}) []scanner_ci.CiPkgs {
		for _, v := range found {
			key := fmt.Sprintf(scanner_ci.CiUniquePkg, v.Name, v.Version)
			if _, ok := filter[key]; !ok {
				filter[key] = struct{}{}
				result = append(result, scanner_ci.CiPkgs{ImageID: ImageID, UniquePkg: key, Layer: v.Layer.Digest, License: v.License})
			}
		}
		return result
	}

	pkgs := make([]scanner_ci.CiPkgs, 0)
	mp := make(map[string]struct{})

	// add os pkgs
	pkgs = addPkgFunc(result.Artifact.Artifact.Packages, pkgs, mp)

	// add lang pkgs
	for _, v := range result.Artifact.Artifact.Applications {
		logging.Get().Debug().Str("appType", v.Type).Int("pkgNum", len(v.Libraries)).Msg("add app pkgs")
		pkgs = addPkgFunc(v.Libraries, pkgs, mp)
	}
	logging.Get().Debug().Int("totalPkgNum", len(pkgs)).Msg("ready to save ci pkgs")
	err := c.dal.CreatePkgs(ctx, pkgs)
	if err != nil {
		logging.Get().Err(err).Msg("create ci pkgs error")
		return err
	}

	logging.Get().Debug().Msg("save ci pkgs ok")
	return nil
}

func (c *Controller) logPostgresPkgImages(ctx context.Context, result scanner_ci.PolicyResult, scanDetails *model.ScanDetailScanImage, ImageID int64) error {
	pkgs := []*scanner_ci.CiPkgImage{}
	mp := make(map[string]struct{})
	for _, v := range scanDetails.VulnDetails {
		for _, vuln := range v.Vulns {
			for _, trivyVuln := range vuln.Trivy {
				tmpPkg := scanner_ci.CiPkgImage{}
				tmpPkg.ImageID = ImageID
				tmpPkg.UniquePkg = fmt.Sprintf(scanner_ci.CiUniquePkg, trivyVuln.PkgName, trivyVuln.InstalledVersion)
				tmpVuln := scanner_ci.CiVulns{Name: vuln.CVEID, PkgName: trivyVuln.PkgName, PkgVersion: trivyVuln.InstalledVersion}
				tmpPkg.UniqueVuln = tmpVuln.GenUniqueVuln()
				key := fmt.Sprintf("%s_%d_%d", tmpPkg.UniquePkg, tmpPkg.UniqueVuln, ImageID)
				if _, ok := mp[key]; ok {
					continue
				}
				mp[key] = struct{}{}
				pkgs = append(pkgs, &tmpPkg)
			}
		}
	}

	err := c.dal.CreatePkgImage(ctx, ImageID, pkgs)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) makeSeverityHistogramAndVulnScore(scanDetails *model.ScanDetailScanImage) {
	sevHistorgram := model.SeverityHistogramInfo{}
	for _, reuslts := range scanDetails.VulnDetails {
		for _, vuln := range reuslts.Vulns {
			for _, trivyVuln := range vuln.Trivy {
				switch trivyVuln.Severity {
				case "CRITICAL":
					sevHistorgram.NumCritical++
				case "HIGH":
					sevHistorgram.NumHigh++
				case "MEDIUM":
					sevHistorgram.NumMedium++
				case "LOW":
					sevHistorgram.NumLow++
				case "UNKNOWN":
					sevHistorgram.NumUnknown++
				}
			}
		}
	}
	scanDetails.SeverityHistogram = sevHistorgram
}

func (c *Controller) AddRHSAAndCnnvd(vulnDetails *model.SingleScanDetail, vulnDetail model.NewVulnDetail, flag int) {
	tmpDetail := vulnDetail
	rhsaFlag := 0
	for _, v := range vulnDetail.Trivy[0].References {
		if strings.Contains(v, "/errata/RHSA") {
			index := strings.LastIndex(v, "/")
			tmpDetail.CVEID = v[index+1:]
			rhsaFlag = 1
			break
		}
	}
	if flag == 0 {
		if rhsaFlag == 1 {
			vulnDetails.Vulns = append(vulnDetails.Vulns, tmpDetail)
		}
		if tmpDetail.Cnnvd.Number != "" {
			tmpDetail.CVEID = tmpDetail.Cnnvd.Number
			vulnDetails.Vulns = append(vulnDetails.Vulns, tmpDetail)
		}
	}
}

func (c *Controller) arrangeVulnDetails(trivyReport *report.Results, scanDetails *model.ScanDetailScanImage) {
	vulnQuery := GetSingleBoltVuln()
	fixedFlag := 0
	for i, v := range *trivyReport {
		mp := make(map[string]*model.NewVulnDetail)
		scanDetails.VulnDetails = append(scanDetails.VulnDetails, model.SingleScanDetail{Class: string(v.Class), Target: v.Target, Type: v.Type})
		// 筛选去重trivy的漏洞
		for _, vuln := range v.Vulnerabilities {
			if fixedFlag == 0 && vuln.FixedVersion != "" {
				fixedFlag = 1
			}
			if detail, ok := mp[vuln.VulnerabilityID]; ok {
				detail.Trivy = append(detail.Trivy, vuln)
			} else {
				tmp := &model.NewVulnDetail{}
				tmp.Trivy = append(tmp.Trivy, vuln)
				mp[vuln.VulnerabilityID] = tmp

			}
		}

		// 整合漏洞数据
		scanDetails.VulnDetails[i].Vulns = make([]model.NewVulnDetail, 0, len(mp))
		for k, trivyDetail := range mp {
			cnvd, cnnvd, err := vulnQuery.GetVulnDetail(k)
			if err != nil {
				trivyDetail.CVEID = k
				scanDetails.VulnDetails[i].Vulns = append(scanDetails.VulnDetails[i].Vulns, *trivyDetail)
				// c.AddRHSAAndCnnvd(&scanDetails.Vulns[i], *trivyDetail, 0)
				continue
			}
			trivyDetail.CVEID = k
			trivyDetail.Cnnvd = cnnvd
			trivyDetail.Cnvd = cnvd
			// c.AddRHSAAndCnnvd(&scanDetails.Vulns[i], *trivyDetail, 0)
			scanDetails.VulnDetails[i].Vulns = append(scanDetails.VulnDetails[i].Vulns, *trivyDetail)
		}
	}
	c.makeSeverityHistogramAndVulnScore(scanDetails)
}

func (c *Controller) logPostgresVuln(ctx context.Context, result scanner_ci.PolicyResult, scanDetails *model.ScanDetailScanImage, imageID int64) error {

	vulns := make([]*scanner_ci.CiVulns, 0, 20)
	vulnImages := make([]*scanner_ci.CiVulnImage, 0, 20)

	// function: check if vuln hit policy
	// todo: save match result to db
	vulnHitFunc := func(result *scanner_ci.PolicyResult, ciVuln *scanner_ci.CiVulns) bool {
		checkFunc := func(vulns []scanner_ci.VulnWrapper, ciVuln *scanner_ci.CiVulns) bool {
			for _, v := range vulns {
				if strings.ToLower(ciVuln.Name) == strings.ToLower(v.VulnerabilityID) &&
					strings.ToLower(ciVuln.PkgName) == strings.ToLower(v.PkgName) &&
					strings.ToLower(ciVuln.PkgVersion) == strings.ToLower(v.InstalledVersion) {
					return true
				}
			}
			return false
		}
		if checkFunc(result.MatchVulns.BlackListResults, ciVuln) {
			return true
		}
		if checkFunc(result.MatchVulns.SeverityResults, ciVuln) {
			return true
		}
		return false
	}

	// function: check if vuln in whitelist result
	// todo: save whitelist result to db
	logging.Get().Debug().Interface("whitelist", result.MatchWhiteListVulns).Msg("recv whitelist result")
	vulnInWhiteListFunc := func(result *scanner_ci.PolicyResult, ciVuln *scanner_ci.CiVulns) bool {
		checkVulnExistFunc := func(cv *scanner_ci.CiVulns, vulns []scanner_ci.PkgVuln, withPkg bool) bool {
			if withPkg {
				for _, v := range vulns {
					if strings.ToLower(v.VulnId) == strings.ToLower(cv.Name) &&
						strings.ToLower(cv.PkgName) == strings.ToLower(v.PkgName) &&
						strings.ToLower(cv.PkgVersion) == strings.ToLower(v.PkgInstalledVersion) {
						return true
					}
				}
			} else {
				for _, v := range vulns {
					if strings.ToLower(v.VulnId) == strings.ToLower(cv.Name) {
						return true
					}
				}
			}

			return false
		}
		if checkVulnExistFunc(ciVuln, result.MatchWhiteListVulns.UnfixedVulns, false) {
			return true
		}
		if checkVulnExistFunc(ciVuln, result.MatchWhiteListVulns.LangPkgVulns, false) {
			return true
		}
		if checkVulnExistFunc(ciVuln, result.MatchWhiteListVulns.VulId, false) {
			return true
		}
		if checkVulnExistFunc(ciVuln, result.MatchWhiteListVulns.PkgVulns, true) {
			return true
		}
		return false
	}

	match := 0
	if result.PolicySnapShot.Vuln.Action == scanner_ci.CiActionAlert {
		match = 1
	}
	if result.PolicySnapShot.Vuln.Action == scanner_ci.CiActionBlock {
		match = 2
	}

	for _, v := range scanDetails.VulnDetails {
		for _, vuln := range v.Vulns {
			tmpMatedate := model.VulnMatedata{}
			if vuln.Cnvd != nil {
				tmpMatedate.CNVDs = vuln.Cnvd
			}
			if vuln.Cnnvd.Number != "" {
				tmpMatedate.CNNVDs = vuln.Cnnvd
			}
			for _, trivyVuln := range vuln.Trivy {
				tmpMate := tmpMatedate
				for _, cvss := range trivyVuln.CVSS {
					tmpMate.CVSS.CVSSv3Score = fmt.Sprintf("%f", cvss.V3Score)
					tmpMate.CVSS.CVSSv3Vector = cvss.V3Vector
					break
				}

				tmpVuln := &scanner_ci.CiVulns{
					Target:      v.Target,
					Name:        vuln.CVEID,
					Namespace:   strings.ToLower(v.Type),
					Description: trivyVuln.Description,
					Link:        trivyVuln.References,
					Severity:    trivyVuln.Severity,
					SeverityInt: int(model.GetSeverityInt(trivyVuln.Severity)),
					Metadata:    &tmpMate,
					PkgName:     trivyVuln.PkgName,
					PkgVersion:  trivyVuln.InstalledVersion,
					FixedBy:     trivyVuln.FixedVersion,
					Class:       v.Class,
				}
				vulns = append(vulns, tmpVuln)
				vulnImage := scanner_ci.CiVulnImage{ImageID: imageID, UniqueVuln: tmpVuln.GenUniqueVuln(), SeverityInt: tmpVuln.SeverityInt}

				// check if vuln hit policy
				if vulnHitFunc(&result, tmpVuln) {
					vulnImage.MatchPolicy = match
				}

				// check if vuln in white list
				if vulnInWhiteListFunc(&result, tmpVuln) {
					vulnImage.White = true
					logging.Get().Debug().
						Str("vulId", tmpVuln.Name).
						Str("pkg", tmpVuln.PkgName).
						Str("installed", tmpVuln.PkgVersion).
						Msg("hit whitelist")
				} else {
					logging.Get().Debug().
						Str("vulId", tmpVuln.Name).
						Str("pkg", tmpVuln.PkgName).
						Str("installed", tmpVuln.PkgVersion).
						Msg("not hit whitelist")
				}

				vulnImages = append(vulnImages, &vulnImage)
			}
		}
	}

	if err := c.dal.CreateCiVuln(ctx, vulns); err != nil {
		// 部分写入失败后还是要写入ivan_scanner_vuln_images表数据，所以不能直接返回
		logging.Get().Err(err).Int64("imageID", imageID).Msg("save-result CreateVuln")
	}

	if err := c.dal.CreateVulnImage(ctx, imageID, vulnImages); err != nil {
		logging.Get().Err(err).Int64("imageID", imageID).Msg("save-result CreateVulnImage")
		return err
	}
	return nil
}

func NewCiController(dal adaptStore.ScanCiInterface) (*Controller, error) {
	c := &Controller{
		policy: &scanner_ci.CiPolicy{},
		dal:    dal,
	}

	matcher, err := vulnmatch.NewMatcher()
	if err != nil {
		return nil, err
	}
	c.matcher = matcher

	return c, nil
}

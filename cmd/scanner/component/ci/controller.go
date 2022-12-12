package ci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	scanVuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/bolt-vuln"
	vulnmatch "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-match"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Controller struct {
	policy  *scanner_ci.CiPolicy
	matcher *vulnmatch.Matcher
	dal     store.ScanCiInterface
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

	err := c.matcher.MatchVulnerability(artifact.Artifact)
	if err != nil {
		logging.Get().Err(err).
			Str("image", artifact.ImageName).
			Str("uuid", artifact.UUID).
			Msg("analyze vuln failed")
		return report.Results{}, err
	}

	return c.matcher.Results(), nil
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
		logging.Get().Err(err).Msgf("log Ci Pkgs error")
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
		flag |= (1 << (scanner_ci.SenSitiveQuestion - 1))
	}
	if len(result.MatchSensitiveFiles.DefaultFiles) > 0 {
		flag |= (1 << (scanner_ci.SenSitiveQuestion - 1))
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
	pkgs := []scanner_ci.CiPkgs{}
	mp := make(map[string]struct{})
	for _, v := range result.Artifact.Artifact.Packages {
		key := fmt.Sprintf("%s:%s", v.Name, v.Version)
		if _, ok := mp[key]; !ok {
			mp[key] = struct{}{}
			pkgs = append(pkgs, scanner_ci.CiPkgs{ImageID: ImageID, UniquePkg: key, Layer: v.Layer.Digest, License: v.License})
		}
	}

	err := c.dal.CreatePkgs(ctx, pkgs)
	if err != nil {
		logging.Get().Logger.Err(err).Msgf("create pkgs error")
		return err
	}
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
				tmpPkg.UniquePkg = fmt.Sprintf("%s:%s", trivyVuln.PkgName, trivyVuln.InstalledVersion)
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
	vulnQuery := scanVuln.GetSingleBoltVuln()
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

	mpBlack := make(map[string]struct{})
	mpWhite := make(map[string]struct{})
	if result.PolicySnapShot.Vuln.Enabled {
		for _, v := range result.MatchVulns.BlackListResults {
			mpBlack[v.VulnerabilityID] = struct{}{}
		}
		for _, v := range result.MatchVulns.SeverityResults {
			mpBlack[v.VulnerabilityID] = struct{}{}
		}
	}
	for _, v := range result.PolicySnapShot.Vuln.WhiteListVulns {
		mpWhite[v] = struct{}{}
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
					SeverityInt: model.GetSeverityInt(trivyVuln.Severity),
					Metadata:    &tmpMate,
					PkgName:     trivyVuln.PkgName,
					PkgVersion:  trivyVuln.InstalledVersion,
					FixedBy:     trivyVuln.FixedVersion,
					Class:       v.Class,
				}
				vulns = append(vulns, tmpVuln)
				vulnImage := scanner_ci.CiVulnImage{ImageID: imageID, UniqueVuln: tmpVuln.GenUniqueVuln(), SeverityInt: tmpVuln.SeverityInt}
				if _, ok := mpBlack[tmpVuln.Name]; ok {
					vulnImage.MatchPolicy = match
				}
				if _, ok := mpWhite[tmpVuln.Name]; ok {
					vulnImage.White = true
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

func NewCiController(dal store.ScanCiInterface) (*Controller, error) {
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

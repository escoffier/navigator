package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	iacModel "gitlab.com/piccolo_su/vegeta/pkg/model/iac"
	goPkgIac "gitlab.com/security-rd/go-pkg/iac"
	goPkgIacConst "gitlab.com/security-rd/go-pkg/iac/consts"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/translate"
	"gorm.io/gorm"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	scannerCI "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) iacOpenApi() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/dockerfile/policy/{name}", api.OpenApiDockerfilePolicy())
		r.Post("/dockerfile/result", api.OpenApiDockerfileResult())
		r.Post("/dockerfile/scan", api.OpenApiDockerfileScan())
	}
}

func (api *api) OpenApiDockerfilePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		name := chi.URLParam(r, "name")

		templateSnapshots, err := iacModel.FindDockerfileTemplateSnapshots(ctx, api.rdb.GetReadDB(), map[string]interface{}{"name": name}, map[string]interface{}{"limit": 1, "order": "id desc"})
		if err != nil || len(templateSnapshots) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileTemplatesByNameEqual err: %v, len: %d", err, len(templateSnapshots))).Msg("FindDockerfileTemplatesByNameEqual fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileTemplatesByNameEqual fails")))
			return
		}

		config, err := iacModel.GetDockerfileConfig(ctx, api.rdb.GetReadDB())
		if err != nil {
			logging.Get().Error().Err(fmt.Errorf("GetDockerfileConfig err: %v", err)).Msg("GetDockerfileConfig fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("GetDockerfileConfig fails")))
			return
		}

		toggle := false
		if config.Status == 1 {
			toggle = true
		}
		rules, err := iacModel.FindDockerfileRules(ctx, api.rdb.GetReadDB(), map[string]interface{}{}, map[string]interface{}{})
		if err != nil {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileRules err: %v", err)).Msg("FindDockerfileRules fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileRules fails")))
			return
		}
		rulesMap := make(map[string]string)
		for i := range rules {
			rulesMap[rules[i].BuiltinID] = rules[i].ThirdPartyID
		}
		thirdPartyRules := make([]string, 0)
		for i := range templateSnapshots[0].Rules {
			if thirdPartyRule, ok := rulesMap[templateSnapshots[0].Rules[i]]; ok {
				thirdPartyRules = append(thirdPartyRules, thirdPartyRule)
			}
		}
		policy := iacModel.DockerfilePolicy{
			Toggle:     toggle,
			Name:       templateSnapshots[0].Name,
			TemplateID: templateSnapshots[0].ID,
			Rules:      thirdPartyRules,
			WhiteList:  config.WhiteList,
			Action:     config.Action,
		}

		response.Ok(w, response.WithItem(policy))
	}
}

func (api *api) OpenApiDockerfileResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := scannerCI.PolicyResult{}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		err = json.Unmarshal(data, &result)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		dockerfilePaths := make([]string, 0)
		for k, _ := range result.Dockerfiles {
			dockerfilePaths = append(dockerfilePaths, k)
		}

		status := result.DockerfilesPolicy.Action
		if result.PolicyResultCode == iacModel.DockerfileRecordStatusExceptionCode {
			status = iacModel.DockerfileRecordStatusException
		}
		if result.PolicyResultCode == iacModel.DockerfileRecordStatusPassCode {
			status = iacModel.DockerfileRecordStatusPass
		}

		dockerfileRecord := iacModel.DockerfileRecord{
			UUID:            result.UUID,
			PipelineName:    result.PipelineName,
			TemplateID:      result.DockerfilesPolicy.TemplateID,
			TemplateName:    result.DockerfilesPolicy.Name,
			FilesCount:      len(result.Dockerfiles),
			DockerfilePaths: dockerfilePaths,
			Status:          status,
			CreatedAt:       time.Now(),
		}

		_, rs, err := iacModel.FindDockerfileRecords(ctx, api.rdb.Get(), map[string]interface{}{"uuid": result.UUID}, map[string]interface{}{})
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileRecords by uuid fails")))
			return
		}
		// 相同uuid的扫描记录已经存在
		if len(rs) > 0 {
			logging.Get().Warn().Str("uuid", result.UUID).Str("pipeline", result.PipelineName).Any("dockerfiles", result.Dockerfiles).Msg("record with same uuid exists")
			RespAndLog(w, ctx,
				NewAnError(http.StatusBadRequest, errors.New("record with same uuid exists")))
			return
		}

		err = api.rdb.Get().Transaction(func(tx *gorm.DB) error {
			dockerfileRecord, err = iacModel.CreateDockerfileRecord(ctx, tx, dockerfileRecord)
			if err != nil {
				logging.Get().Error().Err(fmt.Errorf("CreateDockerfileRecord err: %v", err)).Msg("CreateDockerfileRecord fails")
				return err
			}

			dockerfileResults := make([]iacModel.DockerfileResult, 0)
			for i := range dockerfilePaths {
				scanResult, ok := result.DockerfilesScanResults[dockerfilePaths[i]]
				if !ok {
					logging.Get().Error().Str("dockerfile path", dockerfilePaths[i]).Interface("dockerfile scan results", result.DockerfilesScanResults).Msg("find dockerfile scan result fails")
					continue
				}
				dockerFile, ok := result.Dockerfiles[dockerfilePaths[i]]
				if !ok {
					logging.Get().Error().Str("dockerfile path", dockerfilePaths[i]).Interface("dockerfile scan dockerfiles", result.Dockerfiles).Msg("find dockerfile fails")
					continue
				}
				bsr, err := json.Marshal(scanResult.Result)
				if err != nil {
					logging.Get().Error().Err(err).Msg("marshal scan result fails")
					continue
				}
				successRate := float64(len(result.DockerfilesPolicy.Rules)-len(scanResult.Result)) / float64(len(result.DockerfilesPolicy.Rules))
				resultStatus := iacModel.DockerfileResultStatusPass
				if len(scanResult.Result) != 0 {
					resultStatus = result.DockerfilesPolicy.Action
				}
				dockerfileResults = append(dockerfileResults, iacModel.DockerfileResult{
					RecordID:       dockerfileRecord.ID,
					DockerfilePath: dockerfilePaths[i],
					Dockerfile:     dockerFile,
					Result:         string(bsr),
					HitWhitelist:   scanResult.HitWhitelist,
					SuccessRate:    successRate,
					Status:         resultStatus,
					ParseError:     string(scanResult.ParseErr),
					Error:          scanResult.Error,
					CreatedAt:      time.Now(),
				})
			}

			err = iacModel.CreateDockerfileResultInBatch(ctx, tx, dockerfileResults)
			if err != nil {
				logging.Get().Error().Err(fmt.Errorf("CreateDockerfileResultInBatch err: %v", err)).Msg("CreateDockerfileResultInBatch fails")
				return err
			}
			return nil
		})

		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w)
	}
}

func (api *api) OpenApiDockerfileScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		type request struct {
			TemplateID int    `json:"template_id"`
			Dockerfile string `json:"dockerfile"`
		}

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		if len(req.Dockerfile) == 0 {
			RespAndLog(w, ctx,
				NewAnError(http.StatusBadRequest, errors.New("invalid dockerfile content")))
			return
		}

		dockerfileData := strings.ReplaceAll(req.Dockerfile, "\\n", "\n")
		parseErr, result, err := goPkgIac.RunWithData([]byte(dockerfileData), goPkgIacConst.ScanTypeDockerFile, time.Second*10)
		if err != nil {
			logging.Get().Error().Err(err).Str("dockerfile", req.Dockerfile).Msg("RunWithData fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("RunWithData fails")))
			return
		}

		type resp struct {
			Result      []iacModel.ViewDockerfileScanResult `json:"result"`
			ParseError  string                              `json:"parse_error"`
			ResultCount map[string]int                      `json:"result_count"`
		}

		bf, err := json.Marshal(result.GetFailed().Flatten())
		if err != nil {
			logging.Get().Error().Err(err).Str("dockerfile", req.Dockerfile).Msg("marshal flatten fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("marshal flatten fails")))
			return
		}
		snapshots, err := iacModel.FindDockerfileTemplateSnapshots(ctx, api.rdb.GetReadDB(), map[string]interface{}{"template_id": req.TemplateID}, map[string]interface{}{})
		if err != nil || len(snapshots) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileTemplateSnapshots err: %v, len: %d", err, len(snapshots))).Msg("FindDockerfileTemplateSnapshots fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		filterResult, _, err := iacModel.FilterDockerfileResultByTemplate(ctx, api.rdb.GetReadDB(), string(bf), snapshots[0].ID)
		if err != nil {
			logging.Get().Err(err).Msgf("FilterDockerfileResultByTemplate fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FilterDockerfileResultByTemplate fails")))
			return
		}
		respResult := make([]iacModel.ViewDockerfileScanResult, 0)
		err = json.Unmarshal([]byte(filterResult), &respResult)
		if err != nil {
			logging.Get().Err(err).Msgf("unmarshal result fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("unmarshal result fails")))
			return
		}

		rules, err := iacModel.FindDockerfileRules(ctx, api.rdb.GetReadDB(), map[string]interface{}{}, map[string]interface{}{})
		if err != nil {
			logging.Get().Err(err).Msgf("unmarshal result fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileRules fails")))
			return
		}
		rulesMap := make(map[string]string)
		for i := range rules {
			rulesMap[rules[i].ThirdPartyID] = rules[i].Name
		}

		sort.Slice(respResult, func(i, j int) bool {
			return respResult[i].Location.StartLine < respResult[j].Location.StartLine
		})

		resultCount := make(map[string]int)
		for i := range respResult {
			respResult[i].SeqNo = i + 1
			respResult[i].RuleName = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleName, rulesMap[respResult[i].RuleID], string(lang.Language(r.Context())))
			respResult[i].RuleDescription = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleDescription, respResult[i].RuleDescription, string(lang.Language(r.Context())))
			respResult[i].Description = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleMessage, respResult[i].Description, string(lang.Language(r.Context())))
			respResult[i].Resolution = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleResolution, respResult[i].Resolution, string(lang.Language(r.Context())))
			count, _ := resultCount[respResult[i].Severity]
			resultCount[respResult[i].Severity] = count + 1
			// Dockerfile文件整体的问题，hack成全文高亮
			if respResult[i].Location.StartLine == 0 && respResult[i].Location.EndLine == 0 {
				respResult[i].Location.StartLine = 1
				respResult[i].Location.EndLine = 9999
			}
		}

		res := resp{
			Result:      respResult,
			ParseError:  string(parseErr),
			ResultCount: resultCount,
		}

		response.Ok(w, response.WithItem(res))
	}
}

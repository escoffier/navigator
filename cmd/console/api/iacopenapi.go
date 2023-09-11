package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	iacModel "gitlab.com/piccolo_su/vegeta/pkg/model/iac"
	"gitlab.com/security-rd/go-pkg/logging"
	"io"
	"net/http"
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
		if result.ExitCode == iacModel.DockerfileRecordStatusExceptionCode {
			status = iacModel.DockerfileRecordStatusException
		}
		if result.ExitCode == iacModel.DockerfileRecordStatusPassCode {
			status = iacModel.DockerfileRecordStatusPass
		}

		dockerfileRecord := iacModel.DockerfileRecord{
			PipelineName:    result.PipelineName,
			TemplateID:      result.DockerfilesPolicy.TemplateID,
			TemplateName:    result.DockerfilesPolicy.Name,
			FilesCount:      len(result.Dockerfiles),
			DockerfilePaths: dockerfilePaths,
			Status:          status,
			CreatedAt:       time.Now(),
		}

		dockerfileRecord, err = iacModel.CreateDockerfileRecord(ctx, api.rdb.Get(), dockerfileRecord)
		if err != nil {
			logging.Get().Error().Err(fmt.Errorf("CreateDockerfileRecord err: %v", err)).Msg("CreateDockerfileRecord fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("CreateDockerfileRecord fails")))
			return
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

		err = iacModel.CreateDockerfileResultInBatch(ctx, api.rdb.Get(), dockerfileResults)
		if err != nil {
			logging.Get().Error().Err(fmt.Errorf("CreateDockerfileResultInBatch err: %v", err)).Msg("CreateDockerfileResultInBatch fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("CreateDockerfileResultInBatch fails")))
			return
		}

		response.Ok(w)
	}
}

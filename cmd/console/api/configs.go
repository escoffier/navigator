package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/configs"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/translate"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

const (
	OperatorNameDataManagementConfig = "Data Management Config"
	OperatorNameAccountConfig        = "Account Config"
	OperatorNameLogAuditConfig       = "Log Audit Config"
	OperatorModulePlatform           = "Platform"
	OperatorNameMicrosegConfig       = "Microisolation policy, infrastructure, NMS, crew group, namespace group, and tenant configuration"
	OperatorModuleMicroseg           = "microseg"
)

func (api *api) configs() func(chi.Router) {
	return func(r chi.Router) {
		// 所有配置信息的导入导出
		r.Get("/operatorList", api.getOperator())
		r.Post("/export", api.configsExport())
		r.Post("/import", api.configsImport())
		r.Get("/import/status", api.configsImportStatus())
	}
}

func (api *api) getOperator() http.HandlerFunc {
	type node struct {
		Key   string
		Name  string
		Child []*node `json:"child"`
	}
	return func(w http.ResponseWriter, r *http.Request) {

		microseg := &node{
			Key:  "microseg",
			Name: api.translation.One(translate.DomainConfigInEx, translate.KeyProductCategory, OperatorNameMicrosegConfig, string(lang.Language(r.Context()))),
		}
		mic := node{
			Key:   "mic",
			Name:  api.translation.One(translate.DomainConfigInEx, translate.KeyProductModule, OperatorModuleMicroseg, string(lang.Language(r.Context()))),
			Child: []*node{microseg},
		}
		data := &node{
			Key:  "data",
			Name: api.translation.One(translate.DomainConfigInEx, translate.KeyProductCategory, OperatorNameDataManagementConfig, string(lang.Language(r.Context()))),
		}
		usercenter := &node{
			Key:  "usercenter",
			Name: api.translation.One(translate.DomainConfigInEx, translate.KeyProductCategory, OperatorNameAccountConfig, string(lang.Language(r.Context()))),
		}
		naviaudit := &node{
			Key:  "naviaudit",
			Name: api.translation.One(translate.DomainConfigInEx, translate.KeyProductCategory, OperatorNameLogAuditConfig, string(lang.Language(r.Context()))),
		}
		platform := node{
			Key:   "platform",
			Name:  api.translation.One(translate.DomainConfigInEx, translate.KeyProductModule, OperatorModulePlatform, string(lang.Language(r.Context()))),
			Child: []*node{data, usercenter, naviaudit},
		}

		operatorList := []node{mic, platform}
		response.Ok(w, response.WithItems(operatorList), response.WithApiVersion(dataAPIVersion))
	}
}

// 配置信息的导入导出：
func (api *api) configsExport() http.HandlerFunc {
	type Req struct {
		Config []string
	}
	type Res struct {
		Data []byte
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()

		var confReq Req
		err := util.DecodeJSONBody(w, r, &confReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		data := make(map[string][]byte)
		configsService := configs.GetService()

		// check
		if configsService.GetConfigsStatus() {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewImportStatusError(http.StatusBadRequest, fmt.Errorf("backing up files")))
			return
		}

		var confModuleList []string
		cos := configsService.GetConfigOperator()

		// get user info
		userConfig, err := cos[configs.ConfigDomainPlatformUser].Export(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewGetConfigInfoError(http.StatusInternalServerError,
					fmt.Errorf("failed to get configInfo: %w", err)))
			return
		}
		data[configs.ConfigDomainPlatformUser] = userConfig

		for _, value := range confReq.Config {
			if cos, ok := cos[value]; ok {
				configInfo, err := cos.Export(ctx)
				if err != nil {
					apperror.RespAndLog(w, ctx,
						apperror.NewGetConfigInfoError(http.StatusInternalServerError,
							fmt.Errorf("failed to get configInfo: %w", err)))
					return
				}
				data[value] = configInfo
				confModuleList = append(confModuleList, value)
			} else {
				logging.Get().Error().Err(errors.New("")).Msg("")
			}
		}

		jsonOperatorList, err := json.Marshal(confReq.Config)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to marshal : %w", err)))
			return
		}
		data["operator"] = jsonOperatorList

		jsondata, err := json.Marshal(data)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewGetConfigInfoError(http.StatusInternalServerError,
					fmt.Errorf("failed to get configInfo: %w", err)))
			return
		}

		// AES
		AESData, err := util.AesEncryptCBC(jsondata, configsService.GetAesKey())
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewGetConfigInfoError(http.StatusInternalServerError,
					fmt.Errorf("AesEncryptCBC failed:%w", err)))
			return
		}

		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=export-%s.conf", time.Now().Format("20060102150405")))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(AESData)))
		if _, err := w.Write(AESData); err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewGetConfigInfoError(http.StatusInternalServerError,
					fmt.Errorf("AesEncryptCBC failed:%w", err)))
			return
		}
	}
}

func (api *api) configsImport() http.HandlerFunc {
	type res struct {
		Status string
	}
	return func(w http.ResponseWriter, r *http.Request) {
		configsService := configs.GetService()

		username := request.GetUsernameFromContext(r.Context())
		configsService.SetAperator(username)

		file, _, err := r.FormFile("file")
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed  r.FormFile(\"file\"): %w", err)))
			return
		}
		defer file.Close() // close file

		fileData, err := ioutil.ReadAll(file)
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed  ioutil.ReadAll(file): %w", err)))
			return
		}

		// AES decrypt
		decryptData, err := util.AesDecryptCBC(fileData, configsService.GetAesKey())
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed util.AesDecryptCBC: %w", err)))
			return
		}

		ru := make(map[string][]byte)
		json.Unmarshal(decryptData, &ru)

		// check
		if configsService.GetConfigsStatus() {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewImportStatusError(http.StatusBadRequest, fmt.Errorf("backing up files")))
			return
		}

		go func() {
			err := configsService.ImportRun(ru)
			if err != nil {
				logging.Get().Error().Err(err).Msgf("import failed")
			}
		}()

		res := res{Status: "is backing up"}
		response.Ok(w, response.WithItem(res), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) configsImportStatus() http.HandlerFunc {
	type Res struct {
		Status map[string]string
		Import string
	}
	return func(w http.ResponseWriter, r *http.Request) {
		configsService := configs.GetService()

		resp := Res{
			Status: configsService.GetOperatorStatus(),
			Import: configsService.GetImportStatus(),
		}

		response.Ok(w, response.WithItem(resp), response.WithApiVersion(dataAPIVersion))
	}
}

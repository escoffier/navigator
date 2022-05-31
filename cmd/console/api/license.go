package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/license"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const defaultLicenseTimeout = time.Second * 5

func (api *api) licenseRouter() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/envkey", api.generateEnvironmentKey())
		r.Get("/register/status", api.checkRegisterStatus())
		r.Post("/register", api.licenseRegister())

		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth), authenticator(api.rdb), jwtAccessCheck(api.rdb))
			r.Get("/info", api.getLicenseInfo())
		})
	}
}

// checkActiveStatus check the current register status
func (a *api) checkRegisterStatus() http.HandlerFunc {
	type resp struct {
		Register bool `json:"register"`
		First    bool `json:"first"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultLicenseTimeout)
		defer cancel()

		result := resp{Register: license.ValidateLicense(false).IsValid()}

		has, err := dal.HasUser(ctx, a.rdb.GetReadDB())
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		// not found user, it's first login
		result.First = !has

		response.Ok(w, response.WithItem(result))
	}
}

// generateEnvironmentKey generate a environment key
func (a *api) generateEnvironmentKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		envKey, err := license.GenerateEnvKey()
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithCustomField("envKey", envKey))
	}
}

// licenseRegister active or update a license
func (a *api) licenseRegister() http.HandlerFunc {
	type licenseRegisterReq struct {
		LicenseCode string `json:"licenseCode"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultLicenseTimeout)
		defer cancel()

		req := licenseRegisterReq{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if req.LicenseCode == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'licenseCode'")))
			return
		}

		// 保存license到mysql
		err = a.rdb.Get().Transaction(func(tx *gorm.DB) error {
			tx.Logger = tx.Logger.LogMode(logger.Silent)
			err = tx.WithContext(ctx).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "k"}},
				DoUpdates: clause.AssignmentColumns([]string{"config", "updater", "updated_at"}),
			}).Create(&model.TensorConfig{
				Key:       model.ConfLicense,
				Config:    []byte(req.LicenseCode),
				Creator:   model.GetUsernameFromContext(ctx),
				Updater:   model.GetUsernameFromContext(ctx),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Status:    0,
			}).Error
			if err != nil {
				return err
			}

			// 刷新现在保存的licenseInfo
			return license.RefreshLicenseInfo(req.LicenseCode)
		})

		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidLicenseError(http.StatusBadRequest, err))
			return
		}

		response.Ok(w)
	}
}

// getLicenseInfo get license info
func (a *api) getLicenseInfo() http.HandlerFunc {
	type licenseInfoResp struct {
		SerialNo    string         `json:"serialNo"`
		LicenseType string         `json:"licenseType"`
		ExpireAt    int64          `json:"expireAt"`
		UsedNode    int64          `json:"usedNode"`
		NodeLimit   int64          `json:"nodeLimit"`
		Module      string         `json:"module"`
		RemainDays  int64          `json:"remainDays"`
		Status      license.Status `json:"status"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := licenseInfoResp{}
		if info := license.GetLicenseInfo(); info != nil {
			result.SerialNo = info.SerialNo
			result.LicenseType = info.LicenseType
			result.ExpireAt = info.ExpireAt
			result.NodeLimit = info.NodeLimit
			result.Module = info.Module
			result.RemainDays = int64(time.Until(time.Unix(info.ExpireAt, 0)).Hours() / 24)
			result.Status = license.ValidateLicense(false)

			userNode, err := license.GetUsedNodeNum()
			if err != nil {
				logging.GetLogger().Warn().Err(err).Msg("license.GetUsedNodeNum err")
			}

			result.UsedNode = userNode
		}

		response.Ok(w, response.WithItem(result))
	}
}

func licenseVerify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultLicenseTimeout)
		defer cancel()

		status := license.ValidateLicense(false)
		if !status.IsValid() {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidLicenseError(http.StatusPreconditionFailed,
					fmt.Errorf("license valid: %v", status)))
			return
		}

		// license is valid, pass it through
		next.ServeHTTP(w, r)
	})
}

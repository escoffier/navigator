package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) config() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/resourceUpdateActions", api.listResourceUpdateActions())
		r.Get("/trainingStartWhitelistOption", api.listTrainingStartWhitelistOptions())
		r.Get("/mode", api.listSecurityModes())
	}
}

// @Summary List security modes
// @Description List security modes
// @ID v1-security-mode-list
// @Produce json
// @Success 200 {array} model.SecurityMode
// @Router /api/v1/config/mode [get]
func (api *api) listSecurityModes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		modes := []string{
			string(model.SecurityModeDetection),
			string(model.SecurityModePrevention),
		}

		response.Ok(w,
			response.WithItems(modes),
			response.WithTotalItems(int64(len(modes))),
			response.WithItemsPerPage(2),
			response.WithStartIndex(0),
			response.WithApiVersion(apiVersion))
	}
}

// @Summary List resource update actions
// @Description List resource update actions
// @ID v1-resource-update-actions-list
// @Produce json
// @Success 200 {array} model.ResourceImageChangeAction
// @Router /api/v1/config/resourceUpdateActions [get]
func (api *api) listResourceUpdateActions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actions := []string{
			string(model.ResourceImageChangeActionApplyProfilesToUpdatedResource),
			string(model.ResourceImageChangeActionChangeToAudit),
			string(model.ResourceImageChangeActionPolicyDisable),
		}

		response.Ok(w,
			response.WithItems(actions),
			response.WithTotalItems(int64(len(actions))),
			response.WithItemsPerPage(3),
			response.WithStartIndex(0),
			response.WithApiVersion(apiVersion))
	}
}

// @Summary List training start whitelist options
// @Description List training start whitelist options
// @ID v1-training-start-whitelist-options-list
// @Produce json
// @Success 200 {array} model.TrainingStartWhitelistOption
// @Router /api/v1/config/trainingStartWhitelistOption [get]
func (api *api) listTrainingStartWhitelistOptions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actions := []string{
			string(model.TrainingStartWhitelistOptionFromCurrentProfile),
			string(model.TrainingStartWhitelistOptionFromScratch),
		}

		response.Ok(w,
			response.WithItems(actions),
			response.WithTotalItems(int64(len(actions))),
			response.WithItemsPerPage(2),
			response.WithStartIndex(0),
			response.WithApiVersion(apiVersion))
	}
}

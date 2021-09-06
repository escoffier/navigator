package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/builder"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/policy"
	profileService "gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/profile"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) policy() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.listPolicies())
		r.Post("/", api.addPolicy())
		r.Get("/{policyID}", api.getPolicy())
		r.Put("/{policyID}", api.updatePolicy())
		r.Delete("/{policyID}", api.deletePolicy())
		r.Post("/{policyID}/mode", api.setPolicyMode())
		r.Post("/{policyID}/status", api.setPolicyStatus())
		r.Post("/{policyID}/{resourceID}/attach", api.addResourceToPolicy())
		r.Post("/{policyID}/{resourceID}/detach", api.removeResourceFromPolicy())
		r.Post("/{policyID}/{profileKind}/train/start", api.startTraining())
		r.Post("/{policyID}/{profileKind}/train/stop", api.stopTraining())
		r.Post("/{policyID}/{profileKind}/train/abort", api.abortTraining())
		r.Post("/{policyID}/{profileKind}/train/suspend", api.suspendTraining())
		r.Post("/{policyID}/{profileKind}/train/resume", api.resumeTraining())
		r.Put("/{policyID}/{profileKind}", api.patchPolicyProfile())
		r.Get("/{policyID}/{profileKind}/data", api.listPolicyProfileData())
		r.Post("/{policyID}/{profileKind}/data", api.updateProfile())
	}
}

// @Summary Change policy status
// @Description Change policy status
// @ID v1-policy-set-status
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param enabled body boolean true "enabled"
// @Param policyID path string true "policyID"
// @Router /api/v1/policy/{policyID}/status [post]
func (api *api) setPolicyStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		var data model.SecurityPolicyStatusChangeRequest

		err = util.DecodeJSONBody(w, r, &data)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		p, err := secPolicyService.SetStatus(ctx, policyID, data, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't change security policy status: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*p), response.WithApiVersion(apiVersion))
	}
}

// @Summary Change policy mode
// @Description Change policy mode
// @ID v1-policy-set-mode
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param mode body model.SecurityMode true "mode"
// @Param policyID path string true "policyID"
// @Router /api/v1/policy/{policyID}/mode [post]
func (api *api) setPolicyMode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		var data model.SecurityPolicyModeChangeRequest

		err = util.DecodeJSONBody(w, r, &data)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		p, err := secPolicyService.SetSecurityMode(ctx, policyID, data, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't change security policy mode: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*p), response.WithApiVersion(apiVersion))
	}
}

// @Summary Delete security policy
// @Description Delete security policy
// @ID v1-policy-delete
// @Produce json
// @Param policyID path string true "policyID"
// @Router /api/v1/policy/{policyID} [delete]
func (api *api) deletePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		err = secPolicyService.DeletePolicy(ctx, policyID, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't delete security policy: %w", err))
			return
		}

		response.Ok(w, response.WithApiVersion(apiVersion))
	}
}

// @Summary Get security policy
// @Description Get security policy
// @ID v1-policy-get
// @Produce json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Router /api/v1/policy/{policyID} [get]
func (api *api) getPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		policy, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*policy), response.WithApiVersion(apiVersion))
	}
}

// @Summary List security policies
// @Description List security policies
// @ID v1-policy-list
// @Produce json
// @Success 200 {array} model.SecurityPolicy
// @Param search query string false "search"
// @Param limit query integer false "limit"
// @Param offset query integer false "offset"
// @Param sortOrder query string false "sortOrder"
// @Param sortBy query string false "sortBy"
// @Router /api/v1/policy/ [get]
func (api *api) listPolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		search := r.URL.Query().Get("search")

		sortBy, err := api.sortByFromQuery(r, model.GetDefaultPolicySortableName(), model.GetPolicySortableNames()...)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "asc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		policies, docNum, err := secPolicyService.ListPolicies(ctx, int(offset), int(limit), search, model.GetPolicySortableField(sortBy), sortOrder)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Could not list security policies: %w", err))
			return
		}

		response.Ok(w,
			response.WithItems(policies),
			response.WithTotalItems(int64(docNum)),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset),
			response.WithApiVersion(apiVersion))
	}
}

// @Summary Update security policy
// @Description Update security policy
// @ID v1-policy-update
// @Accept  json
// @Produce json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Param enabled body boolean true "enabled"
// @Param timeout body integer true "timeout"
// @Param trainingStartWhitelistOption body model.TrainingStartWhitelistOption true "trainingStartWhitelistOption"
// @Router /api/v1/policy/{policyID}/{profileKind} [put]
func (api *api) patchPolicyProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		var data model.SecurityPolicyProfilePutRequest

		err = util.DecodeJSONBody(w, r, &data)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		updatedSecPolicy, err := secPolicyService.UpdatePolicyProfile(ctx, policyID, profileKind, data, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't update security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*updatedSecPolicy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Update security policy
// @Description Update security policy
// @ID v1-policy-update
// @Accept  json
// @Produce json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param name body boolean true "enabled"
// @Param description body string true "description"
// @Param resourceImageChangeAction body model.ResourceImageChangeAction true "resourceImageChangeAction"
// @Param policyID path string true "policyID"
// @Router /api/v1/policy/{policyID} [put]
func (api *api) updatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		var data model.SecurityPolicyPutRequest

		err = util.DecodeJSONBody(w, r, &data)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		updatedSecPolicy, err := secPolicyService.UpdatePolicy(ctx, policyID, data, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't update security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*updatedSecPolicy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Create security policy
// @Description Create security policy
// @ID v1-policy-create
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param name body string true "name"
// @Param description body string true "description"
// @Param policyID path string true "policyID"
// @Router /api/v1/policy/ [post]
func (api *api) addPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var data model.SecurityPolicyAddRequest

		err := util.DecodeJSONBody(w, r, &data)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		secPolicy, err := secPolicyService.AddPolicy(ctx, data, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't add security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*secPolicy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Attach resource to policy
// @Description Attach resource to policy
// @ID v1-policy-resource-attach
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param resourceID path string true "resourceID"
// @Router /api/v1/policy//{policyID}/{resourceID}/attach [post]
func (api *api) addResourceToPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*30)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		resourceID, err := getResourceIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read resourceID: %w", err),
					Suberror{"resourceID", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		secPolicy, err := secPolicyService.AddResoruceToPolicy(ctx, policyID, resourceID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't add resource: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*secPolicy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Detach resource from policy
// @Description Detach resource from policy
// @ID v1-policy-resource-detach
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param resourceID path string true "resourceID"
// @Router /api/v1/policy/{policyID}/{resourceID}/detach [post]
func (api *api) removeResourceFromPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*120) // long timeout because onlineVulnerabilities need sync
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		resourceID, err := getResourceIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read resourceID: %w", err),
					Suberror{"resourceID", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		secPolicy, err := secPolicyService.RemoveResourceFromPolicy(ctx, policyID, resourceID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't add security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*secPolicy), response.WithApiVersion(apiVersion))
	}
}

// @Summary List security policy profile data
// @Description List security policy profile data
// @ID v1-policy-profile-data-list
// @Produce json
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Router /api/v1/policy/{policyID}/{profileKind}/data [get]
func (api *api) listPolicyProfileData() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		var sortBy string
		if profileKind == model.SecurityKindApparmor {
			sortBy, err = api.sortByFromQuery(r, model.GetDefaultApparmorSortableName(), model.GetApparmorSortableNames()...)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
			sortBy = model.GetApparmorSortableField(sortBy)
		} else if profileKind == model.SecurityKindCommandWhitelist {
			sortBy, err = api.sortByFromQuery(r, model.GetDefaultCommandWhitelistSortableName(), model.GetCommandWhitelistSortableNames()...)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
			sortBy = model.GetCommandWhitelistSortableField(sortBy)
		} else if profileKind == model.SecurityKindSeccomp {
			sortBy, err = api.sortByFromQuery(r, model.GetDefaultSeccompSortableName(), model.GetSeccompSortableNames()...)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
			sortBy = model.GetSeccompSortableField(sortBy)
		} else {
			RespAndLog(w, ctx,
				NewAnError(http.StatusBadRequest,
					fmt.Errorf("Profile kind %s not supported: %w", profileKind, err)))
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "asc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		secProfileService, exists := profileService.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		profileData, err := secProfileService.ListProfileData(ctx, policyID, profileKind)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Could not list security policies: %w", err))
			return
		}

		var docNum int64
		if profileKind == model.SecurityKindApparmor {
			docNum = int64(len(profileData.ApparmorProfileData))
			results := make([]*model.ApparmorProfileData, len(profileData.ApparmorProfileData))
			for i := range profileData.ApparmorProfileData {
				results[i] = &profileData.ApparmorProfileData[i]
			}
			sort.Slice(results, func(i, j int) bool {
				return api.sortBy(results[i], results[j], sortBy, sortOrder)
			})
			resultsOffset := int(math.Min(float64(offset), float64(len(results))))
			resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))
			response.Ok(w,
				response.WithItems(results[resultsOffset:resultsLimit]),
				response.WithTotalItems(docNum),
				response.WithItemsPerPage(limit),
				response.WithStartIndex(offset),
				response.WithApiVersion(apiVersion))
		} else if profileKind == model.SecurityKindCommandWhitelist {
			docNum = int64(len((*profileData).CommandWhitelistProfileData))
			results := make([]*model.CommandWhitelistProfileData, len(profileData.CommandWhitelistProfileData))
			for i := range profileData.CommandWhitelistProfileData {
				results[i] = &profileData.CommandWhitelistProfileData[i]
			}
			sort.Slice(results, func(i, j int) bool {
				return api.sortBy(results[i], results[j], sortBy, sortOrder)
			})
			resultsOffset := int(math.Min(float64(offset), float64(len(results))))
			resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))
			response.Ok(w,
				response.WithItems(results[resultsOffset:resultsLimit]),
				response.WithTotalItems(docNum),
				response.WithItemsPerPage(limit),
				response.WithStartIndex(offset),
				response.WithApiVersion(apiVersion))
		} else if profileKind == model.SecurityKindSeccomp {
			docNum = int64(len(profileData.SeccompProfileData))
			results := make([]*model.SeccompProfileData, len(profileData.SeccompProfileData))
			for i := range profileData.SeccompProfileData {
				results[i] = &profileData.SeccompProfileData[i]
			}
			sort.Slice(results, func(i, j int) bool {
				return api.sortBy(results[i], results[j], sortBy, sortOrder)
			})
			resultsOffset := int(math.Min(float64(offset), float64(len(results))))
			resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))
			response.Ok(w,
				response.WithItems(results[resultsOffset:resultsLimit]),
				response.WithTotalItems(docNum),
				response.WithItemsPerPage(limit),
				response.WithStartIndex(offset),
				response.WithApiVersion(apiVersion))
		} else {
			RespAndLog(w, ctx,
				NewUnknownSecurityProfileKindError(http.StatusBadRequest,
					fmt.Errorf("Unknown security profile kind")))
			return
		}

	}
}

// @Summary Update policy resource profile
// @Description Update policy resource profile
// @ID v1-policy-profile-update
// @Produce json
// @Accept json
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Param addSeccompProfileData body []model.SeccompProfileData false "addSeccompProfileData"
// @Param addApparmorProfileData body []model.ApparmorProfileData false "addApparmorProfileData"
// @Param addCommandWhitelistProfileData body []model.CommandWhitelistProfileData false "addCommandWhitelistProfileData"
// @Param removeSeccompProfileData body []model.SeccompProfileData false "removeSeccompProfileData"
// @Param removeApparmorProfileData body []model.ApparmorProfileData false "removeApparmorProfileData"
// @Param removeCommandWhitelistProfileData body []model.CommandWhitelistProfileData false "removeCommandWhitelistProfileData"
// @Router /api/v1/policy/{policyID}/{profileKind}/data [put]
func (api *api) updateProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*30)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		var data model.ProfileDataPost

		err = util.DecodeJSONBody(w, r, &data)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		profileService, exists := profileService.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get profile service")))
		}

		err = profileService.UpdatePolicyProfile(ctx, policyID, profileKind, &data, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to update profile: %w", err))
			return
		}

		response.Ok(w, response.WithApiVersion(apiVersion))
	}
}

// @Summary Start profile training
// @Description Start profile training
// @ID v1-policy-profile-train-start
// @Accept json
// @Produce json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Router /api/v1/policy/{policyID}/{profileKind}/train/start [post]
func (api *api) startTraining() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		if profileKind == model.SecurityKindDrift {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Cannot train drift profiles")))
			return
		}

		secProfileBuilderService, exists := builder.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get builder service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		err = secProfileBuilderService.StartTraining(ctx, policyID, profileKind, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't start training: %w", err))
			return
		}

		policy, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*policy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Stop profile training
// @Description Stop profile training
// @ID v1-policy-profile-train-stop
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Router /api/v1/policy/{policyID}/{profileKind}/train/stop [post]
func (api *api) stopTraining() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		p, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get policy: %w", err))
			return
		}

		if profileKind == model.SecurityKindDrift {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Cannot train drift profiles")))
			return
		}

		secProfileBuilderService, exists := builder.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get builder service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		err = secProfileBuilderService.StopTraining(ctx, p, profileKind, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't stop training: %w", err))
			return
		}

		policy, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*policy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Abort profile training
// @Description Abort profile training
// @ID v1-policy-profile-train-abort
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Router /api/v1/policy/{policyID}/{profileKind}/train/abort [post]
func (api *api) abortTraining() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		p, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get policy: %w", err))
			return
		}

		if profileKind == model.SecurityKindDrift {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Cannot train drift profiles")))
			return
		}

		secProfileBuilderService, exists := builder.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get builder service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		err = secProfileBuilderService.AbortTraining(ctx, p, profileKind, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't abort training: %w", err))
			return
		}

		policy, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*policy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Suspend profile training
// @Description Suspend profile training
// @ID v1-policy-profile-train-suspend
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Router /api/v1/policy/{policyID}/{profileKind}/train/suspend [post]
func (api *api) suspendTraining() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		p, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get policy: %w", err))
			return
		}

		if profileKind == model.SecurityKindDrift {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Cannot train drift profiles")))
			return
		}

		secProfileBuilderService, exists := builder.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get builder service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		err = secProfileBuilderService.SuspendTraining(ctx, p, profileKind, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't abort training: %w", err))
			return
		}

		policy, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*policy), response.WithApiVersion(apiVersion))
	}
}

// @Summary Resume profile training
// @Description Resume profile training
// @ID v1-policy-profile-train-resume
// @Produce json
// @Accept json
// @Success 200 {object} model.SecurityPolicy
// @Param policyID path string true "policyID"
// @Param profileKind path string true "profileKind"
// @Router /api/v1/policy/{policyID}/{profileKind}/train/resume [post]
func (api *api) resumeTraining() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyID, err := getPolicyIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read policyID: %w", err),
					Suberror{"policyID", ""}))
			return
		}

		profileKind, err := getProfileKindFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read profileKind: %w", err),
					Suberror{"profileKind", ""}))
			return
		}

		secPolicyService, exists := policy.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get policy service")))
			return
		}

		p, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get policy: %w", err))
			return
		}

		if profileKind == model.SecurityKindDrift {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Cannot train drift profiles")))
			return
		}

		secProfileBuilderService, exists := builder.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get builder service")))
			return
		}

		username := r.Header.Get("username")
		if username == "" {
			username = "unknown"
		}

		err = secProfileBuilderService.ResumeTraining(ctx, p, profileKind, username)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't abort training: %w", err))
			return
		}

		policy, err := secPolicyService.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get security policy: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*policy), response.WithApiVersion(apiVersion))
	}
}

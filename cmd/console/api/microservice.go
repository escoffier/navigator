package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"
	"time"
)

//@Router /api/v1/microservice
func (api *api) Microservice() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/vulnerabilities/details/{namespace}/{resourceKind}/{resourceName}", api.getMicroOnlineVulnerabilityDetails())
		r.Get("/reportsByImage", api.getServiceScannedImages())
		r.Get("/serviceMain", api.getMicroServiceMain())
		r.Post("/focus", api.OptFocus())
		r.Get("/serviceInfo", api.getServiceInfo())
		r.Get("/responsibleSearch", api.responsibleSearch())
		r.Post("/responsibleSubmit", api.responsibleSubmit())
		r.Post("/setServiceAlias", api.setServiceAlias())

	}
}

// @Summary Get service  details of online vulnerabiilty
// @Description Get details of online vulnerabiilty
// @Produce json
// @Router /api/v1/microservice/vulnerabilities/details/{namespace}/{resourceKind}/{resourceName} [get]
// @Param resourceKind query string false "case-sensitive resource kind"
// @Param resourceName query string false "case-sensitive resource name"
func (api *api) getMicroOnlineVulnerabilityDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		namespace := chi.URLParam(r, "namespace")
		if namespace == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Missing param 'namespace'"),
					Suberror{"namespace", ""}))
			return
		}

		resourceName := chi.URLParam(r, "resourceName")
		if resourceName == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Missing param 'resourceName'"),
					Suberror{"resourceName", ""}))
			return
		}

		resourceKind := chi.URLParam(r, "resourceKind")
		if resourceKind == "" && resourceKind != "service" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Missing param 'resourceKind'"),
					Suberror{"resourceKind", "only support service"}))
			return
		}

		vulnDetails, err := api.onlineVulnsSvc.GetOnlineVulnerabilityDetails(ctx, namespace, resourceKind, resourceName)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(*vulnDetails))
	}
}

// @Summary List service images and their vulnerabilities
// @Description List images and their vulnerabilities
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param maxImageAgeInHours query int false "return only images that have only scans younger than this number; 0 or empty disables"
// @Param sortBy query string false "finishedAt/overallSeverity/repository/tag/imageDigest"
// @Param namespace query string
// @Patam selecter query string "only service"
// @Patam svcname  query string "servername"
// @Router /api/v1/microservice/reportsByImage [get]
func (api *api) getServiceScannedImages() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		namespace := r.URL.Query().Get("namespace")
		if namespace == "" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("should not be empty"),
				Suberror{"namespace", "string"}))
			return
		}

		selecter := r.URL.Query().Get("selecter")
		if selecter != "service" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("current only support service"),
				Suberror{"selecter", "service"}))
			return
		}
		svcname := r.URL.Query().Get("svcname")
		if svcname == "" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("should not be empty"),
				Suberror{"svcname", "string"}))
			return
		}

		sortBy, err := api.sortByFromQuery(r, model.GetDefaultScannedImagesSortableName(), model.GetScannedImagesSortableNames()...)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)
		items, docNum, err := api.scannerService.GetServiceScannedImages(ctx, offset, limit, model.ScannedImagesSortableFields[sortBy], namespace, svcname, sortOrder)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}
		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary get  service  main page
// @GET
// @Produce json
// @Router /api/v1/microservice/serviceMain
func (api *api) getMicroServiceMain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()
		itemType := r.URL.Query().Get("itemType")
		if itemType == "" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("should not be empty"),
				Suberror{"itemType", "string myFocus/all"}))
			return
		}
		search := r.URL.Query().Get("search")

		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Error when getting token & claims from context: %w", err)))
			return
		}
		if token == nil || !token.Valid {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Token empty or invalid")))
			return
		}

		username, _ := claims[JWT_KEY_USERNAME].(string)
		offset, limit := api.getOffsetAndLimit(r)

		if itemType == "all" {
			items, docNum, err := api.microService.GetAllServiceInfo(ctx, offset, limit, username, search)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
			response.Ok(w,
				response.WithItems(items),
				response.WithTotalItems(docNum),
				response.WithItemsPerPage(limit),
				response.WithStartIndex(offset))
		} else {
			items, docNum, err := api.microService.GetMyFocusServiceInfo(ctx, offset, limit, username, search)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
			response.Ok(w,
				response.WithItems(items),
				response.WithTotalItems(docNum),
				response.WithItemsPerPage(limit),
				response.WithStartIndex(offset))
		}
	}
}

// @Summary Add new Focus
// @POST
// @Produce json
// @Router  /api/v1/microservice/addFocus
func (api *api) OptFocus() http.HandlerFunc {
	type resp struct {
		Status string `json:"status"`
	}
	type param struct {
		Namespace string `json:"namespace" bson:"namespace"`
		SvcName   string `json:"svcName" bson:"svcName"`
		OptType   string `json:"optType" bson:"optType"` //Focus
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var param param

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*120)
		defer cancel()

		err := util.DecodeJSONBody(w, r, &param)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Error when getting token & claims from context: %w", err)))
			return
		}
		if token == nil || !token.Valid {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Token empty or invalid")))
			return
		}

		username, _ := claims[JWT_KEY_USERNAME].(string)

		err = api.microService.SetMyFocusServiceInfo(ctx, param.Namespace, param.SvcName, username, param.OptType)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't Opt Focus: %w", err))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}
}

// @Summary get  service  main page info
// @GET
// @Produce json
// @Router /api/v1/microservice/serviceInfo
func (api *api) getServiceInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()
		namespace := r.URL.Query().Get("namespace")
		if namespace == "" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("should not be empty"),
				Suberror{"namespace", "string "}))
			return
		}
		svcname := r.URL.Query().Get("svcname")
		if svcname == "" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("should not be empty"),
				Suberror{"svcname", "string "}))
			return
		}

		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Error when getting token & claims from context: %w", err)))
			return
		}
		if token == nil || !token.Valid {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Token empty or invalid")))
			return
		}

		username, _ := claims[JWT_KEY_USERNAME].(string)

		items, err := api.microService.GetServiceInfo(ctx, namespace, svcname, username)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}
		response.Ok(w,
			response.WithItems(items))

	}
}

// @Summary search responsible
// @GET
// @Produce json
// @Router /api/v1/microservice/responsibleSearch
func (api *api) responsibleSearch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()
		search := r.URL.Query().Get("search")

		items, err := api.microService.GetUserNameInfo(ctx, search)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}
		response.Ok(w,
			response.WithItems(items))
	}
}

// @Summary Add service alias
// @POST
// @Produce json
// @Router  /api/v1/microservice//setServiceAlias
func (api *api) responsibleSubmit() http.HandlerFunc {
	type resp struct {
		Status string `json:"status"`
	}
	type param struct {
		Namespace       string   `json:"namespace" bson:"namespace"`
		SvcName         string   `json:"svcName" bson:"svcName"`
		ResponsibleName []string `json:"respName" bson:"respName"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var param param

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10) // long timeout because onlineVulnerabilities need sync
		defer cancel()

		err := util.DecodeJSONBody(w, r, &param)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		err = api.microService.SetRespServiceInfo(ctx, param.Namespace, param.SvcName, param.ResponsibleName)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't submit Responsible: %w", err))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}
}

// @Summary set service alias
// @POST
// @Produce json
// @Router  /api/v1/microservice/responsibleSubmit
func (api *api) setServiceAlias() http.HandlerFunc {
	type resp struct {
		Status string `json:"status"`
	}
	type param struct {
		Namespace string `json:"namespace" bson:"namespace"`
		SvcName   string `json:"svcName" bson:"svcName"`
		AliasName string `json:"aliasName" bson:"aliasName"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var param param

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10) // long timeout because onlineVulnerabilities need sync
		defer cancel()

		err := util.DecodeJSONBody(w, r, &param)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		err = api.microService.SetAliasName(ctx, param.Namespace, param.SvcName, param.AliasName)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("couldn't submit serviceAlias: %w", err))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}
}

package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/resource"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) resource() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/container", api.listResources())
		r.Get("/name", api.listResourceNames())
		r.Get("/namespace", api.listNamespaces())
		r.Get("/cluster", api.listClusters())
		r.Get("/kind", api.listResourceKinds())
	}
}

// @Summary Get resources
// @Description Get resources
// @ID v1-resource-list
// @Produce json
// @Param search query string false "search"
// @Param limit query integer false "limit"
// @Param offset query integer false "offset"
// @Param sortOrder query string false "sortOrder"
// @Param sortBy query string false "sortBy"
// @Param cluster query string false "cluster"
// @Param namespace query string false "namespace"
// @Param kind query string false "kind"
// @Param name query string false "name"
// @Param containerName query string false "containerName"
// @Param unattached query boolean false "unattached"
// @Success 200 {array} model.SecurityPolicyResource
// @Router /api/v1/resource/container [get]
func (api *api) listResources() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		search := r.URL.Query().Get("search")

		sortBy, err := api.sortByFromQuery(r, model.GetDefaultResourceSortableName(), model.GetResourceSortableNames()...)
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

		cluster := r.URL.Query().Get("cluster")
		namespace := r.URL.Query().Get("namespace")
		resourceKindStr := r.URL.Query().Get("kind")
		name := r.URL.Query().Get("name")
		containerName := r.URL.Query().Get("containerName")
		unattachedStr := r.URL.Query().Get("unattached")

		var resourceKind model.KubernetesResource
		var unattached bool

		if resourceKindStr != "" {
			resourceKind = model.KubernetesResource(resourceKindStr)
		} else {
			resourceKind = model.KubernetesResourceAny
		}

		if !api.validSecurityResource(resourceKind) {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("Invalid value for 'kind' query param")))
			return
		}

		if unattachedStr != "" {
			if unattachedStr != "false" && unattachedStr != "true" {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Invalid values for 'active' query param: allowed true/false")))
				return
			}
			var err error
			unattached, err = strconv.ParseBool(unattachedStr)
			if err != nil {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to parse 'unattached' query param")))
				return
			}
		} else {
			unattached = true
		}

		secResourceService, exists := resource.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get resource service")))
			return
		}

		resources, docNum, err := secResourceService.ListResources(
			ctx, cluster, namespace, resourceKind, name, containerName, unattached, int(offset), int(limit), model.GetResourceSortableField(sortBy), sortOrder, search)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't list resources: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(resources),
			response.WithTotalItems(int64(docNum)),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset),
			response.WithApiVersion(apiVersion))
	}
}

// @Summary Get resource names
// @Description Get resource names
// @ID v1-name-list
// @Produce json
// @Param cluster query string false "name"
// @Param namespace query string false "namespace"
// @Param kind query string false "kind"
// @Param unattached query boolean false "unattached"
// @Success 200 {array} string
// @Router /api/v1/resource/name/ [get]
func (api *api) listResourceNames() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		cluster := r.URL.Query().Get("cluster")
		namespace := r.URL.Query().Get("namespace")
		resourceKindStr := r.URL.Query().Get("kind")
		unattachedStr := r.URL.Query().Get("unattached")

		var resourceKind model.KubernetesResource
		var unattached bool

		if resourceKindStr != "" {
			resourceKind = model.KubernetesResource(resourceKindStr)
		} else {
			resourceKind = model.KubernetesResourceAny
		}

		if !api.validSecurityResource(resourceKind) {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("Invalid value for 'kind' query param")))
			return
		}

		if unattachedStr != "" {
			if unattachedStr != "false" && unattachedStr != "true" {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Invalid values for 'active' query param: allowed true/false")))
				return
			}
			var err error
			unattached, err = strconv.ParseBool(unattachedStr)
			if err != nil {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to parse 'unattached' query param")))
				return
			}
		} else {
			unattached = true
		}

		secResourceService, exists := resource.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get resource service")))
			return
		}

		resources, docNum, err := secResourceService.ListResourceNames(ctx, cluster, namespace, resourceKind, unattached)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't list resource kinds: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(resources),
			response.WithTotalItems(int64(docNum)),
			response.WithItemsPerPage(int64(docNum)),
			response.WithStartIndex(0),
			response.WithApiVersion(apiVersion))
	}
}

// @Summary Get resource kinds
// @Description Get resource kinds
// @ID v1-kind-list
// @Produce json
// @Param cluster query string false "name"
// @Param namespace query string false "namespace"
// @Param unattached query boolean false "unattached"
// @Success 200 {array} string
// @Router /api/v1/resource/kind/ [get]
func (api *api) listResourceKinds() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		cluster := r.URL.Query().Get("cluster")
		namespace := r.URL.Query().Get("namespace")
		unattachedStr := r.URL.Query().Get("unattached")

		var unattached bool

		if unattachedStr != "" {
			if unattachedStr != "false" && unattachedStr != "true" {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Invalid values for 'active' query param: allowed true/false")))
				return
			}
			var err error
			unattached, err = strconv.ParseBool(unattachedStr)
			if err != nil {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to parse 'unattached' query param")))
				return
			}
		} else {
			unattached = true
		}

		secResourceService, exists := resource.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get resource service")))
			return
		}

		resources, docNum, err := secResourceService.ListResourceKinds(ctx, cluster, namespace, unattached)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't list resource kinds: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(resources),
			response.WithTotalItems(int64(docNum)),
			response.WithItemsPerPage(int64(docNum)),
			response.WithStartIndex(0),
			response.WithApiVersion(apiVersion))
	}
}

// @Summary Get namespaces
// @Description Get namespaces
// @ID v1-namespace-list
// @Produce json
// @Param cluster query string false "name"
// @Param unattached query boolean false "unattached"
// @Success 200 {array} string
// @Router /api/v1/resource/namespace/ [get]
func (api *api) listNamespaces() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		cluster := r.URL.Query().Get("cluster")
		unattachedStr := r.URL.Query().Get("unattached")

		var unattached bool

		if unattachedStr != "" {
			if unattachedStr != "false" && unattachedStr != "true" {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Invalid values for 'active' query param: allowed true/false")))
				return
			}
			var err error
			unattached, err = strconv.ParseBool(unattachedStr)
			if err != nil {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to parse 'unattached' query param")))
				return
			}
		} else {
			unattached = true
		}

		secResourceService, exists := resource.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get resource service")))
			return
		}

		resources, docNum, err := secResourceService.ListNamespaces(ctx, cluster, unattached)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't list namespaces: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(resources),
			response.WithTotalItems(int64(docNum)),
			response.WithItemsPerPage(int64(docNum)),
			response.WithStartIndex(0),
			response.WithApiVersion(apiVersion))
	}
}

// @Summary Get clusters
// @Description Get clusters
// @ID v1-cluster-list
// @Param unattached query boolean false "unattached"
// @Success 200 {array} string
// @Produce json
// @Router /api/v1/resource/cluster/ [get]
func (api *api) listClusters() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		unattachedStr := r.URL.Query().Get("unattached")

		var unattached bool

		if unattachedStr != "" {
			if unattachedStr != "false" && unattachedStr != "true" {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Invalid values for 'active' query param: allowed true/false")))
				return
			}
			var err error
			unattached, err = strconv.ParseBool(unattachedStr)
			if err != nil {
				RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to parse 'unattached' query param")))
				return
			}
		} else {
			unattached = true
		}

		secResourceService, exists := resource.Get()
		if !exists {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get resource service")))
			return
		}

		resources, docNum, err := secResourceService.ListClusters(ctx, unattached)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't list clusters: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(resources),
			response.WithTotalItems(int64(docNum)),
			response.WithItemsPerPage(int64(docNum)),
			response.WithStartIndex(0),
			response.WithApiVersion(apiVersion))
	}
}

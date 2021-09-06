package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/mcuadros/go-version"
	param "github.com/oceanicdev/chi-param"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	apiVersion = "2.0"
)

type api struct {
	ctx context.Context
}

func newAPI(
	ctx context.Context,
) *api {
	return &api{
		ctx: ctx,
	}
}

func (api *api) getTimeoutCtx(timeout ...time.Duration) (context.Context, context.CancelFunc) {
	if timeout == nil {
		return context.WithTimeout(api.ctx, 10*time.Second)
	}
	return context.WithTimeout(api.ctx, timeout[0])
}

func (api *api) getOffsetAndLimit(r *http.Request) (int64, int64) {
	offset, err := param.QueryUint(r, "offset")
	if err != nil {
		offset = 0
	}
	limit, err := param.QueryUint(r, "limit")
	if err != nil {
		limit = 500
	}
	if limit > 10000 {
		limit = 10000
	}
	return int64(offset), int64(limit)
}

func (api *api) sortOrderFromQuery(r *http.Request, defaultSortOrder string) (string, error) {
	sortOrder := r.URL.Query().Get("sortOrder")
	if sortOrder == "" {
		sortOrder = defaultSortOrder
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		return "desc", NewFieldError(http.StatusBadRequest,
			fmt.Errorf("invalid sortOrder param value (allowed: asc/desc)"),
			Suberror{"sortOrder", "allowed: asc/desc"})
	}
	return sortOrder, nil
}

func (api *api) sortByFromQuery(r *http.Request, firstAllowedValue string, nextAllowedValues ...string) (string, error) {
	sortBy := r.URL.Query().Get("sortBy")
	if sortBy == "" {
		sortBy = firstAllowedValue
	}

	nextAllowedValues = append(nextAllowedValues, firstAllowedValue)
	for _, val := range nextAllowedValues {
		if sortBy == val {
			return sortBy, nil
		}
	}

	allowed := fmt.Sprintf("allowed: %s", strings.Join(nextAllowedValues, "/"))
	return firstAllowedValue, NewFieldError(http.StatusBadRequest,
		fmt.Errorf("invalid kind param value (%s)", allowed),
		Suberror{"sortBy", allowed})
}

func (api *api) sortBy(first interface{}, second interface{}, sortBy string, sortOrder string) bool {
	d1 := reflect.ValueOf(first).Elem()
	d2 := reflect.ValueOf(second).Elem()
	for i := 0; i < d1.NumField(); i++ {
		typeField := d1.Type().Field(i).Name
		if typeField == strings.Title(sortBy) {
			val1 := d1.Field(i)
			val2 := d2.Field(i)
			switch val1.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if sortOrder == "asc" {
					return val1.Int() < val2.Int()
				}
				return val1.Int() > val2.Int()
			case reflect.String:
				matched, err := regexp.MatchString(`^\d+\.\d+\.\d+$`, val1.String())
				// Do we want to handle it or just do other sorting then?
				if err != nil {
					logging.GetLogger().Warn().
						Str("val1", val1.String()).
						Msg("Error regex matching in sorting")
					matched = false
				}
				if matched {
					if sortOrder == "asc" {
						return version.CompareSimple(val1.String(), val2.String()) < 0
					}
					return version.CompareSimple(val2.String(), val1.String()) > 0
				}
				if sortOrder == "asc" {
					return val1.String() < val2.String()
				}
				return val1.String() > val2.String()
			}
		}
	}
	if sortOrder == "asc" {
		return fmt.Sprintf("%v", first) < fmt.Sprintf("%v", second)
	}
	return fmt.Sprintf("%v", first) > fmt.Sprintf("%v", second)
}

func getPolicyIDFromURL(r *http.Request) (int, error) {
	policyID := chi.URLParam(r, "policyID")
	if policyID == "" {
		return -1, errors.New("policyID is not provided")
	}
	return strconv.Atoi(policyID)
}

func getProfileIDFromURL(r *http.Request) (int, error) {
	profileID := chi.URLParam(r, "profileID")
	if profileID == "" {
		return -1, errors.New("profileID is not provided")
	}
	return strconv.Atoi(profileID)
}

func getProfileKindFromURL(r *http.Request) (model.SecurityKind, error) {
	profileKind := chi.URLParam(r, "profileKind")
	if profileKind == "" {
		return model.SecurityKindAny, errors.New("profileKind is not provided")
	}
	if profileKind != string(model.SecurityKindApparmor) &&
		profileKind != string(model.SecurityKindCommandWhitelist) &&
		profileKind != string(model.SecurityKindSeccomp) &&
		profileKind != string(model.SecurityKindDrift) {
		return model.SecurityKindAny, errors.New("unknown profileKind provided")
	}
	return model.SecurityKind(profileKind), nil
}

func getResourceIDFromURL(r *http.Request) (int, error) {
	resourceID := chi.URLParam(r, "resourceID")
	if resourceID == "" {
		return -1, errors.New("resourceID is not provided")
	}
	return strconv.Atoi(resourceID)
}

func (api *api) validSecurityKind(secKind model.SecurityKind) bool {
	if secKind != model.SecurityKindAny && secKind != model.SecurityKindApparmor &&
		secKind != model.SecurityKindCommandWhitelist && secKind != model.SecurityKindDrift &&
		secKind != model.SecurityKindSeccomp {
		return false
	}
	return true
}

func (api *api) validSecurityResource(kind model.KubernetesResource) bool {
	if kind != model.KubernetesResourceAny && kind != model.KubernetesResourceCronJob &&
		kind != model.KubernetesResourceDaemonset && kind != model.KubernetesResourceDeployment &&
		kind != model.KubernetesResourceJob && kind != model.KubernetesResourcePod &&
		kind != model.KubernetesResourceReplicaSet && kind != model.KubernetesResourceStatefulset {
		return false
	}
	return true
}

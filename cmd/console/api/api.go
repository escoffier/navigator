package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	"github.com/mcuadros/go-version"
	param "github.com/oceanicdev/chi-param"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type api struct {
	tokenAuth   *jwtauth.JWTAuth
	rdb         *databases.RDBInstance
	microsegURL string
	webhookURL  *url.URL

	scannerURL        string
	exportURL         string
	secProfileCoreURL string
	redisClient       *redis.Client
	harborClient      *harbor.HarborRESTClient
	ecCli             pb.EventsCenterBizServiceClient
	esCli             *elastic.ESClient

	// For managing state in Harbor plugin API
	abortAnyNewScansBool int32

	httpAuditDisabled bool
}

func newAPI(
	tokenAuth *jwtauth.JWTAuth,
	rdb *databases.RDBInstance,
	scannerURL string,
	exportURL string,
	secProfileCoreURL string,
	microsegURL string,
	webhookURL string,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
	ecCli pb.EventsCenterBizServiceClient,
	esCli *elastic.ESClient,
	httpAuditDisabled bool,

) *api {
	whUrl, err := url.Parse(webhookURL)
	if err != nil {
		logging.Get().Err(err).Msgf("invalid webhook url: %v", whUrl)
		whUrl = nil
	}

	return &api{
		tokenAuth:         tokenAuth,
		rdb:               rdb,
		scannerURL:        scannerURL,
		exportURL:         exportURL,
		secProfileCoreURL: secProfileCoreURL,
		microsegURL:       microsegURL,
		webhookURL:        whUrl,
		redisClient:       redisClient,
		harborClient:      harborClient,
		ecCli:             ecCli,
		esCli:             esCli,
		httpAuditDisabled: httpAuditDisabled,
	}
}

func (api *api) NotFound(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusNotFound)
	rw.Header().Add("Content-Type", "text/plain; charset=UTF-8")
	rw.Write([]byte("404 Not Found"))
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
	if limit > 1000 {
		limit = 1000
	}
	return int64(offset), int64(limit)
}

func (api *api) sortOrderFromQuery(r *http.Request, defaultSortOrder string) (string, error) {
	sortOrder := r.URL.Query().Get("sortOrder")
	if sortOrder == "" {
		sortOrder = defaultSortOrder
	}
	if sortOrder != orderAsc && sortOrder != orderDesc {
		return "desc", NewFieldError(http.StatusBadRequest,
			fmt.Errorf("invalid sortOrder param value (allowed: asc/desc)"),
			Suberror{Location: keySortOrder, Message: sortOrderEnums})
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
		Suberror{Location: "sortBy", Message: allowed})
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
				if sortOrder == orderAsc {
					return val1.Int() < val2.Int()
				}
				return val1.Int() > val2.Int()
			case reflect.String:
				matched, err := regexp.MatchString(`^\d+\.\d+\.\d+$`, val1.String())
				// Do we want to handle it or just do other sorting then?
				if err != nil {
					logging.Get().Warn().
						Str("val1", val1.String()).
						Msg("Error regex matching in sorting")
					matched = false
				}
				if matched {
					if sortOrder == orderAsc {
						return version.CompareSimple(val1.String(), val2.String()) < 0
					}
					return version.CompareSimple(val2.String(), val1.String()) > 0
				}
				if sortOrder == orderAsc {
					return val1.String() < val2.String()
				}
				return val1.String() > val2.String()
			}
		}
	}
	if sortOrder == orderAsc {
		return fmt.Sprintf("%v", first) < fmt.Sprintf("%v", second)
	}
	return fmt.Sprintf("%v", first) > fmt.Sprintf("%v", second)
}

func getClusterIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	clusterID := chi.URLParam(r, "clusterID")
	if clusterID == "" {
		return primitive.NilObjectID, errors.New("clusterID is not provided")
	}
	return primitive.ObjectIDFromHex(clusterID)
}

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-redis/redis/v8"
	param "github.com/oceanicdev/chi-param"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type api struct {
	tokenAuth   *jwtauth.JWTAuth
	rdb         *databases.RDBInstance
	microsegURL string
	webhookURL  *url.URL

	scannerURL   string
	exportURL    string
	sherlockURL  string
	redisClient  *redis.Client
	harborClient *harbor.HarborRESTClient
	esCli        *elastic.ESClient

	// For managing state in Harbor plugin API
	abortAnyNewScansBool int32

	httpAuditDisabled bool
}

func newAPI(
	tokenAuth *jwtauth.JWTAuth,
	rdb *databases.RDBInstance,
	scannerURL string,
	exportURL string,
	sherlockURL string,
	microsegURL string,
	webhookURL string,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
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
		sherlockURL:       sherlockURL,
		microsegURL:       microsegURL,
		webhookURL:        whUrl,
		redisClient:       redisClient,
		harborClient:      harborClient,
		esCli:             esCli,
		httpAuditDisabled: httpAuditDisabled,
	}
}

func (api *api) NotFound(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusNotFound)
	rw.Header().Add("Content-Type", "text/plain; charset=UTF-8")
	rw.Write([]byte("404 Not Found"))
}
func (api *api) getOffsetAndLimit(r *http.Request) (int, int) {
	offset, err := param.QueryInt(r, "offset")
	if err != nil {
		offset = 0
	}
	limit, err := param.QueryInt(r, "limit")
	if err != nil {
		limit = 500
	}
	if limit > 1000 {
		limit = 1000
	}
	return offset, limit
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

func getClusterIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	clusterID := chi.URLParam(r, "clusterID")
	if clusterID == "" {
		return primitive.NilObjectID, errors.New("clusterID is not provided")
	}
	return primitive.ObjectIDFromHex(clusterID)
}

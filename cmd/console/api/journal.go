package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"

	es "gitlab.com/piccolo_su/vegeta/pkg/elasticsearch"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) journals() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/search", api.searchJournals())
	}
}

// @Summary Search Journals
// @Description search api to ElasticSearchj for journals
// @ID v1-journals-search
// @Produce json
// @Param from query int false "from timestamp"
// @Param to query int false "to timestamp"
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param message query string false "search message"
// @Router /api/v1/journals/search [get]
func (api *api) searchJournals() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		index, buf, err := es.GetQueryFromRequest(r)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("error in creating the query from request: %s", err))
			return
		}

		res, err := es.HandleESResponse(api.esClient.Search(
			api.esClient.Search.WithContext(context.Background()),
			api.esClient.Search.WithIndex(index),
			api.esClient.Search.WithBody(&buf),
			api.esClient.Search.WithTrackTotalHits(true),
		))
		if err != nil {
			response.InternalError(w, fmt.Sprintf("error in ElasticSearch: %s", err))
			return
		}
		response.Ok(w, response.WithItem(res))
	}
}

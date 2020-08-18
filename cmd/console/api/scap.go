package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScapTask())
		r.Post("/check", api.scapcheck())
	}
}

// @Summary Get a scap task by scaptask ID
// @Description Get a scap task
// @ID v1-scap-task-get
// @Produce json
// @Param taskID path string true "scap task ID"
// @Router /api/v1/scap/task/{taskID} [get]
func (api *api) getScapTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		taskObjectID, err := getTaskObjectIDFromURL(r)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		// from mongo
		var result model.ScapTask
		err = api.mongodb.Collection(model.ScapTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}).Decode(&result)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, result)
	}
}

// @Summary Tell scap to check
// @Description Tell scap to check
// @ID v1-scap-check
// @Produce json
// @Router /api/v1/scap/check [post]
func (api *api) scapcheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		task := &model.ScapTask{
			ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
			ScannerType: "kubebench_all",
			Status:      model.ScannerStatusReady,
			CreatedAt:   time.Now().Unix(),
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()
		_, err := api.mongodb.Collection(model.ScapTasksCollection).
			InsertOne(ctx, task)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, task)
	}
}

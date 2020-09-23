package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) scanner() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScannerTask())
		r.Post("/scan", api.scan())
	}
}

func getTaskObjectIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	taskID := chi.URLParam(r, "taskID")
	if taskID == "" {
		return primitive.NilObjectID, errors.New("taskID is not provided")
	}
	return primitive.ObjectIDFromHex(taskID)
}

// @Summary Get a scan task by scantask ID
// @Description Get a scan task
// @ID v1-scanner-task-get
// @Produce json
// @Param taskID path string true "scan task ID"
// @Router /api/v1/scanner/task/{taskID} [get]
func (api *api) getScannerTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		taskObjectID, err := getTaskObjectIDFromURL(r)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("taskID not provided")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("taskID", ""))
			return
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		// from mongo
		var result model.ScanTask
		err = api.mongodb.Collection(model.ScanTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}).Decode(&result)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w, response.WithItem(result))
	}
}

// @Summary Tell scanner to scan an image
// @Description Tell scanner to scan an image
// @ID v1-scanner-scan
// @Produce json
// @Param image body string true "image name"
// @Param rescan body bool true "force rescan the image"
// @Router /api/v1/scanner/scan [post]
func (api *api) scan() http.HandlerFunc {
	type param struct {
		ImageName   string `json:"image"`
		ForceRescan bool   `json:"rescan"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var param param
		err := decodeJSONBody(w, r, &param)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Failed to decode json")
			response.Bad(w, response.WithMessage(locale.Error(locale.MalformedRequestError, r)))
			return
		}

		jsonValue, err := json.Marshal(param)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Failed to marshal json")
			response.Bad(w, response.WithMessage(locale.Error(locale.MalformedRequestError, r)))
			return
		}

		client := http.Client{
			Timeout: 10 * time.Second,
		}
		resp, err := client.Post(
			fmt.Sprintf("%s/api/v1/scan/one", api.scannerURL),
			"application/json",
			bytes.NewBuffer(jsonValue),
		)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("POST to Scanner failed")
			response.InternalError(w, response.WithMessage(locale.Error(locale.ConnectionError, r)))
			return
		}

		_, err = io.Copy(w, resp.Body)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't respond with response from canner")
			response.InternalError(w, response.WithMessage(locale.Error(locale.HTTPResponseError, r)))
			return
		}
	}
}

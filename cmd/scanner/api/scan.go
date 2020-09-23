package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

// ScanResultResponse is the response for scan result
type ScanResultResponse struct {
	ImageName string `json:"imageName"`
	DBId      string `json:"dbId"`
}

func (api *api) scan() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/one", api.scanOne())
	}
}

// @Summary Scan one image
// @Description Scan one image
// @ID v1-scan-one-post
// @Produce json
// @Param image body string true "image name"
// @Param rescan body bool true "force rescan the image"
// @Router /api/v1/scan/one [post]
func (api *api) scanOne() http.HandlerFunc {
	type image struct {
		ImageName   string `json:"image"`
		ForceRescan bool   `json:"rescan"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var task model.ScanTask

		imageToScan := &image{}
		err := decodeJSONBody(w, r, imageToScan)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		task, err = component.NewTaskByNameTag(imageToScan.ImageName, imageToScan.ForceRescan)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		// persist the task to Mongo
		ctx, cancel := context.WithTimeout(api.ctx, 10*time.Second)
		defer cancel()

		task.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		_, err = api.mongodb.Collection(model.ScanTasksCollection).InsertOne(ctx, task)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		// add the task to redclair
		api.redclair.AddScanTask(task)

		response.Ok(w, response.WithItem(task))
	}
}

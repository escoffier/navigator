package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/defense"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"
	"time"
)

func (api *api) defenseOpenApi() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/baitServices", api.getBaitServicesOpenApi())
		r.Get("/baitImages", api.getBaitImagesOpenApi())
		r.Get("/baitImage", api.getBaitImageOpenApi())
		r.Post("/baitService", api.addBaitServiceOpenApi())
		r.Put("/baitService", api.updateBaitServicesOpenApi())
		r.Delete("/baitService", api.deleteBaitServiceOpenApi())
	}
}

func (api *api) getBaitServicesOpenApi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var neeCheckAlert = false
		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Info().Msg("cluster_key param is empty.")
			clusterKey = ""
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.GetLogger().Info().Msg("namespace param is empty.")
			namespace = ""
		}

		name, err := param.QueryString(r, "name")
		if err != nil {
			logging.GetLogger().Info().Msg("name param is empty.")
			name = ""
		}

		resourceName, err := param.QueryString(r, "resource_name")
		if err != nil {
			logging.GetLogger().Info().Msg("resource_name param is empty.")
			resourceName = ""
		}

		baitIds, err := param.QueryUint32Array(r, "bait_id")
		if err != nil {
			logging.GetLogger().Info().Msg("bait_name param is empty.")
			baitIds = nil
		}

		haveAlerts, err := param.QueryBool(r, "have_alerts")
		if err != nil {
			logging.GetLogger().Info().Msg("have_alerts param is empty.")
		} else {
			neeCheckAlert = true
		}

		status, err := param.QueryString(r, "status")
		if err != nil {
			logging.GetLogger().Info().Msg("status param is empty.")
			status = ""
		}

		defenseSvc, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get bait service failed")))
			return
		}

		queryOpt := dal.BaitsQuery()
		if clusterKey != "" {
			queryOpt = queryOpt.WithCluster(clusterKey)
		}
		if namespace != "" {
			queryOpt = queryOpt.WithMultiColumnQuery("namespace", namespace)
		}
		if name != "" {
			queryOpt = queryOpt.WithMultiColumnQuery("name", name)
		}
		if resourceName != "" {
			queryOpt = queryOpt.WithMultiColumnQuery("resource_name", resourceName)
		}
		if len(baitIds) > 0 {
			queryOpt = queryOpt.WithInConditionCustom("bait_id", baitIds)
		}
		if status != "" {
			queryOpt = queryOpt.WithWorkloadStatus(status)
		}
		if neeCheckAlert {
			queryOpt = queryOpt.WithAlerts(haveAlerts)
		}

		baitServices, err := defenseSvc.GetBaitServices(ctx, queryOpt, limit, offset)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetBaitImages error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		cnt, err := defenseSvc.CountBaitServices(ctx, queryOpt)
		if err != nil {
			logging.GetLogger().Err(err).Msg("CountBaitImages error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		var resp []*BaitServiceOpenApi
		for _, bait := range baitServices {
			prefixName := fmt.Sprintf("%s-%s", bait.Prefix, bait.ResourceName)
			alertEvents, err := defenseSvc.GetAlertEvent(ctx, bait.ClusterKey, bait.Namespace, prefixName, 0, bait.CreatedAt.UnixMilli())
			if err != nil {
				logging.GetLogger().Warn().Msgf("get alert events for %s failed", prefixName)
			}

			resp = append(resp, &BaitServiceOpenApi{
				ID:           bait.ID,
				Status:       bait.WorkLoadStatus,
				Name:         bait.Name,
				BaitType:     bait.BaitName,
				BaitId:       bait.BaitId,
				ClusterKey:   bait.ClusterKey,
				Namespace:    bait.Namespace,
				ResourceName: bait.ResourceName,
				PrefixName:   fmt.Sprintf("%s-%s", bait.Prefix, bait.ResourceName),
				Image:        bait.Image,
				OutboundOff:  bait.OutboundOff,
				RegistryId:   bait.RegistryId,
				CreateAt:     bait.CreatedAt,
				Events:       alertEvents,
			})
		}
		response.Ok(w, response.WithItems(resp), response.WithTotalItems(cnt),
			response.WithStartIndex(int64(offset+len(resp))))
	}
}

func (api *api) getBaitImagesOpenApi() http.HandlerFunc {
	const maxBaitImageNum = 20
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			limit = maxBaitImageNum
		}

		defenseSvc, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get bait service failed")))
			return
		}

		baitImages, err := defenseSvc.GetBaitImages(ctx, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetBaitImages error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		totalCnt, err := defenseSvc.CountBaitImages(ctx)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		var resp []*BaitImageOpenApi
		for _, img := range baitImages {
			resp = append(resp, &BaitImageOpenApi{
				ID:            img.ID,
				Name:          img.Name,
				BaitName:      img.BaitName,
				Vulnerability: img.Vulnerability,
				Description:   img.Description,
				Prefix:        img.EventPrefix,
			})
		}
		response.Ok(w, response.WithItems(resp), response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(offset+len(resp))))
	}
}

func (api *api) getBaitImageOpenApi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		id, err := param.QueryUint32(r, "id")
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no bait image id in params")))
			return
		}
		defenseSvc, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get bait service failed")))
			return
		}
		baitImage, err := defenseSvc.GetBaitImageByID(ctx, id)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		repoInfos, err := defenseSvc.GetBaitImageRepoInfo(ctx, baitImage.Name)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		resp := BaitImageOpenApi{
			ID:            baitImage.ID,
			Name:          baitImage.Name,
			BaitName:      baitImage.BaitName,
			Repositories:  repoInfos,
			Vulnerability: baitImage.Vulnerability,
			Description:   baitImage.Description,
			Prefix:        baitImage.EventPrefix,
		}
		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) addBaitServiceOpenApi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var baitService model.BaitService
		err := util.DecodeJSONBody(w, r, &baitService)
		if err != nil {
			RespAndLog(w, ctx,
				NewAddBaitServiceError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if !isResourceNameValid(baitService.ResourceName) {
			RespAndLog(w, ctx,
				NewAddBaitServiceError(http.StatusInternalServerError,
					fmt.Errorf("resource name is invalid")))
			return
		}
		defenseService, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAddBaitServiceError(http.StatusInternalServerError, errors.New("defense service instance get error")))
			return
		}
		err = checkBaitService(ctx, defenseService, &baitService)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		baitService.ID = util.GenerateUUID(baitService.ClusterKey, baitService.Namespace, baitService.Name)
		// TODO: maybe deleted later
		if baitService.Replica == 0 {
			baitService.Replica = 1
		}
		err = defenseService.AddBaitService(ctx, &baitService)

		if err != nil {
			err = convertErr(err)
			RespAndLog(w, ctx, err)
			return
		}
		response.Ok(w)
	}
}

func (api *api) updateBaitServicesOpenApi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)

		defer cancel()

		var baitService model.BaitService
		err := util.DecodeJSONBody(w, r, &baitService)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if baitService.ID == 0 {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("invalid bait service id")))
			return
		}
		defenseService, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("defense service instance get error")))
			return
		}
		err = checkBaitServicenName(ctx, defenseService, &baitService)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		err = defenseService.UpdateBaitService(ctx, &baitService)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to update bait service : %w", err)))
			return
		}
		response.Ok(w)
	}
}

func (api *api) deleteBaitServiceOpenApi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		id, err := param.QueryUint32(r, "id")
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no bait service id in params")))
			return
		}

		defenseService, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("defense service instance get error")))
			return
		}
		err = defenseService.DeleteBaitService(ctx, id)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		response.Ok(w)
	}
}

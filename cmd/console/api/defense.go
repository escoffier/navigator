package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/pb"

	"github.com/go-chi/chi"
	"github.com/go-sql-driver/mysql"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/defense"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

func (api *api) defense() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/baitService", api.getBaitService())
		r.Get("/baitServices", api.getBaitServices())
		r.Get("/baitImages", api.getBaitImages())
		r.Get("/baitImage", api.getBaitImage())
		r.Put("/baitService", api.addBaitService())
		r.Post("/baitService", api.updateBaitServices())
		r.Get("/baitEvents", api.getBaitEvents())
		r.Delete("/baitService", api.deleteBaitService())
	}
}

func (api *api) getBaitService() http.HandlerFunc {
	type BaitService struct {
		ID           uint32            `json:"id"`
		Name         string            `json:"name"`
		BaitType     string            `json:"baitType"`
		BaitId       uint32            `json:"baitId"`
		ClusterKey   string            `json:"clusterKey"`
		Namespace    string            `json:"namespace"`
		ResourceName string            `json:"resource_name"`
		PrefixName   string            `json:"prefixName"`
		Image        string            `json:"image"`
		RegistryId   int               `json:"registryId"`
		OutboundOff  bool              `json:"outboundOff"`
		Events       []*defense.Signal `json:"events"`
		Status       string            `json:"status"`
		CreateAt     time.Time         `json:"crateAt"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

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
			name = ""
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
			queryOpt = queryOpt.WithNamespace(namespace)
		}
		if name != "" {
			queryOpt = queryOpt.WithName(name)
		}

		baitService, err := defenseSvc.GetBaitService(ctx, queryOpt)
		if err != nil {
			return
		}
		prefixName := fmt.Sprintf("%s-%s", baitService.Prefix, baitService.ResourceName)
		alertEvents, err := defenseSvc.GetAlertEvent(ctx, clusterKey, namespace, prefixName, 0, baitService.CreatedAt.UnixMilli())
		if err != nil {
			return
		}
		resp := BaitService{
			ID:           baitService.ID,
			Status:       "online",
			Name:         baitService.Name,
			BaitType:     baitService.BaitName,
			BaitId:       baitService.BaitId,
			ClusterKey:   baitService.ClusterKey,
			Namespace:    baitService.Namespace,
			ResourceName: baitService.ResourceName,
			PrefixName:   fmt.Sprintf("%s-%s", baitService.Prefix, baitService.ResourceName),
			Image:        baitService.Image,
			OutboundOff:  baitService.OutboundOff,
			RegistryId:   baitService.RegistryId,
			CreateAt:     baitService.CreatedAt,
			Events:       alertEvents,
		}
		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) getBaitServices() http.HandlerFunc {
	type BaitService struct {
		ID           uint32            `json:"id"`
		Status       string            `json:"status"`
		Name         string            `json:"name"`
		BaitType     string            `json:"baitType"`
		BaitId       uint32            `json:"baitId"`
		ClusterKey   string            `json:"clusterKey"`
		Namespace    string            `json:"namespace"`
		ResourceName string            `json:"resourceName"`
		PrefixName   string            `json:"prefixName"`
		Image        string            `json:"image"`
		OutboundOff  bool              `json:"outboundOff"`
		RegistryId   int               `json:"registryId"`
		Events       []*defense.Signal `json:"events"`
		CreateAt     time.Time         `json:"crateAt"`
	}
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

		var resp []*BaitService
		for _, bait := range baitServices {
			prefixName := fmt.Sprintf("%s-%s", bait.Prefix, bait.ResourceName)
			alertEvents, err := defenseSvc.GetAlertEvent(ctx, bait.ClusterKey, bait.Namespace, prefixName, 0, bait.CreatedAt.UnixMilli())
			if err != nil {
				logging.GetLogger().Warn().Msgf("get alert events for %s failed", prefixName)
			}

			resp = append(resp, &BaitService{
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

func (api *api) addBaitService() http.HandlerFunc {
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
		//TODO: maybe deleted later
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

func (api *api) updateBaitServices() http.HandlerFunc {

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

func (api *api) deleteBaitService() http.HandlerFunc {
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

func (api *api) getBaitImages() http.HandlerFunc {
	type BaitImages struct {
		ID            uint32 `json:"id"`
		Name          string `json:"name"`
		BaitName      string `json:"baitName"`
		Vulnerability string `json:"vulnerability"`
		Description   string `json:"description"`
		Prefix        string `json:"prefix"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
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

		var resp []*BaitImages
		for _, img := range baitImages {
			resp = append(resp, &BaitImages{
				ID:            img.ID,
				Name:          img.Name,
				BaitName:      img.BaitName,
				Vulnerability: img.Vulnerability,
				Description:   img.Description,
				Prefix:        img.EventPrefix,
			})
		}
		response.Ok(w, response.WithItems(resp), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(offset+len(resp))))
	}
}

func (api *api) getBaitImage() http.HandlerFunc {
	type BaitImages struct {
		ID            uint32                 `json:"id"`
		Name          string                 `json:"name"`
		BaitName      string                 `json:"baitName"`
		Repositories  []*defense.ImageDetail `json:"repositories"`
		Vulnerability string                 `json:"vulnerability"`
		Description   string                 `json:"description"`
		Prefix        string                 `json:"prefix"`
	}

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
		resp := BaitImages{
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

func (api *api) getBaitEvents() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Info().Msg("cluster_key param is empty.")
			clusterKey = ""
		}

		queryOpt := dal.BaitsQuery()
		if clusterKey != "" {
			queryOpt = queryOpt.WithCluster(clusterKey)
		}

		defenseSvc, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get bait service failed")))
			return
		}

		baitServices, err := defenseSvc.GetBaitServices(ctx, queryOpt, 1000, 0)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetBaitImages error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		items := []*signal{}
		for _, bait := range baitServices {
			req := &pb.GetSignalsReq{
				OffsetSignalID: "",
				// Limit:          uint32(100),
				SortOrder: pb.SortOrder_Desc,
				Filter: map[string]string{
					"cluster":   clusterKey,
					"namespace": bait.Namespace,
					"nodeKey":   bait.ResourceName,
				},
				Lang: string(lang.Language(ctx)),
			}
			resp, err := api.ecCli.GetSignals(ctx, req)
			if err != nil {
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
				return
			}

			signals := convertSignals(resp.Signals)
			items = append(items, signals...)
		}
		response.Ok(w, response.WithItems(items), response.WithTotalItems(int64(len(items))),
			response.WithStartIndex(int64(0)))
	}
}

func isResourceNameValid(name string) bool {
	if len(name) > 50 {
		return false
	}
	result := validation.IsDNS1123Subdomain(name)
	if len(result) != 0 {
		return false
	}
	result = validation.IsDNS1035Label(name)
	if len(result) != 0 {
		return false
	}
	result = validation.IsDNS1123Label(name)
	return len(result) == 0
}

func checkBaitService(ctx context.Context, s *defense.TensorDefenseService, baitService *model.BaitService) error {
	if len(baitService.Name) > 63 {
		return NewAddBaitServiceError(http.StatusInternalServerError, fmt.Errorf("bait name more than 63 char"))
	}
	queryOpt := dal.BaitsQuery()
	baitServices, _ := s.GetBaitServices(ctx, queryOpt, 100000, 0)
	for _, s := range baitServices {
		if s.Name == baitService.Name {
			return NewBaitNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated bait service name"))
		}
		if s.ClusterKey == baitService.ClusterKey && s.Namespace == baitService.Namespace && s.ResourceName == baitService.ResourceName {
			return NewResourceNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated resource name"))
		}
	}

	return nil
}

func checkBaitServicenName(ctx context.Context, s *defense.TensorDefenseService, baitService *model.BaitService) error {
	queryOpt := dal.BaitsQuery()
	queryOpt.WithName(baitService.Name)
	cnt, _ := s.CountBaitServices(ctx, queryOpt)
	logging.GetLogger().Info().Msgf("found %d bait service", cnt)
	if cnt > 0 {
		return NewBaitNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated bait service name"))
	}
	return nil
}

func convertErr(err error) error {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		if mysqlErr.Number == 1062 {
			err = NewBaitNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated bait service name"))
		}
	} else if k8serr.IsAlreadyExists(err) {
		err = NewBaitNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated bait service name"))
	} else {
		err = NewAddBaitServiceError(http.StatusInternalServerError, err)
	}
	return err
}

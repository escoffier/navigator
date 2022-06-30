package component

import (
	"context"
	"fmt"
	"net/http"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageSrvInterface interface {
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error)
	CreateScanImageTask(ctx context.Context, param model.ImageListParam, taskInfo task.UpdateTaskInfo) error
	GetRegistryProject(ctx context.Context, param GetRegistryProjectParam) ([]RegistryRepo, error)
	GetScanOneStatus(ctx context.Context, imgID int64) (*model.ImageListResponse, error)
}

type ImageSrv struct {
	dbdal       store.ScannerDalInterface
	scanTaskDal store.ScanTaskInterface
	registryDal store.RegistryDal
}

func NewImageService(
		dbdal store.ScannerDalInterface,
		registryDal store.RegistryDal,
		scanTaskDal store.ScanTaskInterface,
) *ImageSrv {
	return &ImageSrv{
		dbdal:       dbdal,
		scanTaskDal: scanTaskDal,
		registryDal: registryDal,
	}
}

func (s *ImageSrv) GetScanOneStatus(ctx context.Context, imgID int64) (*model.ImageListResponse, error) {
	info, _, err := s.ListImageWithScanInfo(ctx, model.ImageListParam{ImageIds: []int64{imgID}}, model.EmptyFilterForTotalQuery())
	if err != nil {
		logging.Get().Err(err).Int64("ImageID", imgID).Msg("GetScanOneStatus")
		return nil, err
	}
	if len(info) == 0 {
		return nil, fmt.Errorf("not fond image:%d", imgID)
	}
	return info[0], nil
}

func (s *ImageSrv) ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error) {
	res := make([]*model.ImageListResponse, 0)

	param.Deserialize()
	logging.Get().Info().Interface("param", param).Msg("ListImageWithScanInfo")

	registryIds := make([]int64, 0)
	// 查询未删除的仓库
	noDeleteRegistries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
	if err != nil {
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(noDeleteRegistries) == 0 {
		return res, 0, nil
	}
	regMap := make(map[int64]*model.Registry)

	for i := range noDeleteRegistries {
		registryIds = append(registryIds, noDeleteRegistries[i].ID)
		regMap[noDeleteRegistries[i].ID] = &noDeleteRegistries[i]
	}

	projects := make([]store.RegProject, 0)
	for i := range param.Repos {
		projects = append(projects, store.RegProject{
			RegistryID: param.Repos[i].RegistryID,
			Project:    param.Repos[i].RepoName,
		})
	}

	daoParam := store.SearchImageParam{
		Projects:     projects,
		RegistryIds:  registryIds,
		FromType:     param.GetFromType(),
		ImageType:    param.ImageAttr.ImageType,
		Keyword:      param.Keyword,
		NodeHostname: param.NodeHostname,
		OmitFields:   []string{"config_json", "manifest_v1_json", "manifest_v2_json"},
		UUIDs:        param.UUIDs,
		Fields:       param.Fields,
		StartID:      param.StartID,
	}
	// 查在线
	onlineSQL := fmt.Sprintf("select distinct a.id  from  %s a  join %s b  on  a.image_uuid = b.image_uuid where a.registry_id IN (%s) and b.status = 0 ", model.ImageList{}.TableName(), model.TensorContainer{}.TableName(), util.JoinInt64Slice(registryIds, ","))

	online, err := s.dbdal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSQL})
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.GetOnlineImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	onlineIds := make([]int64, 0)
	onlineMap := make(map[int64]bool)
	for i := range online {
		onlineIds = append(onlineIds, online[i].ID)
		onlineMap[online[i].ID] = true
	}
	inIds, notInIds := make([]int64, 0), make([]int64, 0)
	if param.Online == consts.TrueString {
		if len(inIds) > 0 {
			inIds = util.GetIntersectionSetForInt64(inIds, onlineIds)
		} else {
			inIds = append(inIds, onlineIds...)
		}
		if len(inIds) == 0 {
			return res, 0, nil
		}
	} else if param.Online == consts.FalseString {
		notInIds = append(notInIds, onlineIds...)
	}

	// 可信镜像的筛选
	trustedImages, err := s.dbdal.SearchTrustedImageIDs(ctx, store.SearchTrustedImageParam{IsTrusted: consts.TrueString})
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.SearchQuestionInfo")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	trustedIds := make([]int64, 0)
	trustedMap := make(map[int64]bool)
	for i := range trustedImages {
		trustedIds = append(trustedIds, trustedImages[i])
		trustedMap[trustedImages[i]] = true
	}

	if param.ImageAttr.Trusted != "" {
		if param.ImageAttr.Trusted == consts.TrueString {
			if param.AttrIntersection == consts.AndString && len(trustedIds) == 0 {
				return res, 0, nil
			}
			daoParam.TrustedImageIds = trustedIds
		} else if param.ImageAttr.Trusted == consts.FalseString {
			daoParam.NotTrustedImageIds = trustedIds
		}
	}

	inIds = util.DeDuplicationInt64Slice(inIds)
	if len(param.ImageIds) > 0 {
		if len(inIds) > 0 {
			inIds = util.GetIntersectionSetForInt64(inIds, param.ImageIds)
		} else {
			inIds = param.ImageIds
		}
	}
	daoParam.InIds = inIds
	daoParam.NotInIds = util.DeDuplicationInt64Slice(notInIds)
	daoParam.AttrFlag = param.GenAttrFlag()
	daoParam.SecurityIssueFlag = param.GenSecurityIssueFlag()
	daoParam.AttrIntersection = param.AttrIntersection
	daoParam.IssueIntersection = param.IssueIntersection
	daoParam.ScanStatusFlag = param.ScanStatusFlag

	logging.Get().Info().Interface("daoParam", daoParam).Interface("filter", filter).Msg("SearchImageWithScan.SearchImage")

	images, cnt, err := s.dbdal.SearchImage(ctx, daoParam, filter)
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.SearchImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	logging.Get().Info().Int64("count", cnt).Int("iamgeLength", len(images)).Msg("SearchImageWithScan.SearchImage")

	if len(images) == 0 {
		return res, 0, nil
	}

	// 转换数据
	for i := range images {
		ans := model.ImageListResponse{
			ID:            images[i].ID,
			Digest:        images[i].Digest,
			NodeIP:        images[i].NodeIP,
			Online:        onlineMap[images[i].ID],
			FromType:      images[i].FromTypeToString(),
			SecurityIssue: make([]model.SecurityIssue, 0),
			ImageAttr:     model.ImageAttrResponse{Trusted: trustedMap[images[i].ID]},
			UUID:          images[i].ImageUUID,
			FullRepoName:  images[i].FullRepoName,
			Tag:           images[i].Tags,
			RegistryID:    images[i].RegistryID,
			RegistryUrl:   images[i].Library,
			Os:            images[i].OS,
			NodeHostname:  images[i].NodeHostname,
			Flag:          images[i].Flag,
			Project:       images[i].Project,
			LastSyncAt:    images[i].LastFullSyncAt * 1000, // 前端要求毫秒时间戳
			Registry:      regMap[images[i].RegistryID],
			UniqueImage:   images[i].UniqueImage,
		}
		res = append(res, &ans)
	}

	if param.JustReturnImage {
		return res, cnt, nil
	}

	imageIds := make([]int64, 0)
	for i := range images {
		imageIds = append(imageIds, images[i].ID)
	}

	// 获取镜像的扫描的状态
	statusMap := make(map[int64]*model.SubTask)
	subtasks, err := s.scanTaskDal.SearchSubTasksWithScanStatus(ctx, imageIds, nil)
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.SearchSubTasksWithStatusFilter")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	logging.Get().Info().Int("subtaskLength", len(subtasks)).Msg("SearchImageWithScan.SearchSubTasksWithScanStatus")
	for i := range subtasks {
		statusMap[subtasks[i].ImageID] = &subtasks[i]
	}

	// 镜像评分
	fields := []string{"vuln_score", "sensitive_score", "virus_score", "webshell_score", "id", "image_id"}
	if param.ReturnMalicious {
		fields = append(fields, "malicious_info_json")
	}
	scs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: imageIds, Fields: fields}, nil)
	if err != nil {
		logging.Get().Err(err).Msg("SearchImages.SearchScanImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	logging.Get().Info().Int("subtasscs", len(scs)).Msg("SearchImageWithScan.SearchScanImage")

	scanMap := make(map[int64]*model.ScanImage)
	for i := range scs {
		scanMap[scs[i].ImageID] = &scs[i]
	}

	// 转换数据
	for i := range res {
		res[i].Registry = regMap[res[i].RegistryID]
		res[i].Subtasks = statusMap[res[i].ID]
		res[i].ScanInfo = scanMap[res[i].ID]

		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (s *ImageSrv) CreateScanImageTask(ctx context.Context, param model.ImageListParam, taskInfo task.UpdateTaskInfo) error {
	param.JustReturnImage = true
	param.Fields = []string{"id"}
	images, _, err := s.ListImageWithScanInfo(ctx, param, model.EmptyFilterForTotalQuery())
	if err != nil {
		logging.Get().Err(err).Msg("CreateScanImageTask find image error")
		return err
	}

	imgIds := make([]int64, 0)
	for i := range images {
		imgIds = append(imgIds, images[i].ID)
	}
	ts := task.NewTaskSrv()

	if err := ts.GenerateScanTask(ctx, imgIds, taskInfo); err != nil {
		logging.Get().Err(err).Msg("add full scan task failed")
		return response.NewHttpError(http.StatusBadRequest, err)
	}
	logging.Get().Info().Msg("add full scan task end")
	return nil
}

func (s *ImageSrv) GetRegistryProject(ctx context.Context, param GetRegistryProjectParam) ([]RegistryRepo, error) {

	repos, err := s.dbdal.GroupRegistryProject(ctx, store.GroupRegistryRepoParam{ProjectKeyword: param.ProjectKeyword, RegID: param.RegID})
	if err != nil {
		logging.Get().Err(err).Msg("GetRegistryProject.GroupRegistryProject")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	resMap := make(map[int64][]store.RegProject)
	for i := range repos {
		repos[i].Name = repos[i].Project
	}
	// 查出所有的registry
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
	if err != nil {
		logging.Get().Err(err).Msg("GetRegistryProject.SearchRegistry")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	regMap := make(map[int64]model.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}

	for i := range repos {
		if _, ok := regMap[repos[i].RegistryID]; !ok {
			continue
		}
		repo := repos[i]
		repo.Key = fmt.Sprintf("%d,%s", repo.RegistryID, repo.Project)

		if resMap[repo.RegistryID] == nil {
			resMap[repo.RegistryID] = make([]store.RegProject, 0)
		}
		resMap[repo.RegistryID] = append(resMap[repo.RegistryID], repo)
	}
	res := make([]RegistryRepo, 0)
	for k, v := range resMap {
		res = append(res, RegistryRepo{
			RegistryID: k,
			Projects:   v,
			URL:        regMap[k].Url,
			Name:       regMap[k].Name,
			Key:        fmt.Sprintf("%d", k),
		})
	}
	return res, nil
}

type GetRegistryProjectParam struct {
	RegID          int64
	ProjectKeyword string
}

type RegistryRepo struct {
	RegistryID int64              `json:"registryID"`
	Name       string             `json:"name"` // 用于前端展示
	URL        string             `json:"url"`
	Projects   []store.RegProject `json:"projects"`
	Key        string             `json:"key"`
}

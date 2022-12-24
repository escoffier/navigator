package component

import (
	"context"
	"fmt"
	"net/http"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageSrvInterface interface {
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error)
	CreateScanImageTask(ctx context.Context, param model.ImageListParam, taskInfo task.UpdateTaskInfo) error
	GetRegistryProject(ctx context.Context, param GetRegistryProjectParam) ([]RegistryRepo, error)
	ImageIssueStatistic(ctx context.Context, imageID int64) (*model.SecurityIssueOverview, error)
	ImageBaseDetail(ctx context.Context, imageID int64) (*model.ImageBaseResponse, error)
}

type ImageSrv struct {
	dbdal         store.ScannerDalInterface
	scanTaskDal   store.ScanTaskInterface
	registryDal   store.RegistryDal
	webshellDal   store.WebshellDalInterface
	vulnDal       store.VulnDalInterface
	scanResultDal store.ImageScanResultDal
}

func NewImageService(
	dbdal store.ScannerDalInterface,
	registryDal store.RegistryDal,
	scanTaskDal store.ScanTaskInterface,
	vulnDal store.VulnDalInterface,
	scanResultDal store.ImageScanResultDal,
	webshellDal store.WebshellDalInterface,
) *ImageSrv {
	return &ImageSrv{
		dbdal:         dbdal,
		scanTaskDal:   scanTaskDal,
		registryDal:   registryDal,
		vulnDal:       vulnDal,
		scanResultDal: scanResultDal,
		webshellDal:   webshellDal,
	}
}

func (s *ImageSrv) ImageIssueStatistic(ctx context.Context, imageID int64) (*model.SecurityIssueOverview, error) {
	// base info
	filter := &model.Filter{Limit: 1}
	images, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{InIds: []int64{imageID}}, filter)
	if err != nil {
		return nil, err
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("not find image:%d", imageID)
	}
	image := images[0]
	res := &model.SecurityIssueOverview{}

	// webshell
	// _, webshellCnt, err := s.scanResultDal.SearchWebShell(ctx, store.SearchImageScanResultParam{ImageID: imageID}, filter)
	// if err != nil {
	// 	return nil, err
	// }
	// sensitiveFile
	_, sensitiveCnt, err := s.scanResultDal.SearchSensitive(ctx, store.SearchImageScanResultParam{ImageID: imageID}, filter)
	if err != nil {
		return nil, err
	}
	// vuln
	_, vulnCnt, err := s.vulnDal.SearchVuln(ctx, store.SearchVulnParam{ImageIds: []int64{imageID}}, nil)
	if err != nil {
		return nil, err
	}
	// env
	_, envCnt, err := s.scanResultDal.SearchImageEnv(ctx, store.SearchImageScanResultParam{ImageID: imageID, NormalEnv: consts.FalseString}, filter)
	if err != nil {
		return nil, err
	}
	// software
	_, softCnt, err := s.scanResultDal.SearchSoftware(ctx, store.SearchImageScanResultParam{ImageID: imageID, Flag: util.SetBit1(uint64(0), model.FlagHasSoftware)}, filter)
	if err != nil {
		return nil, err
	}

	// virus
	_, virusCnt, err := s.scanResultDal.SearchVirus(ctx, store.SearchImageScanResultParam{ImageID: imageID}, filter)
	if err != nil {
		return nil, err
	}

	// license
	_, licenseCnt, err := s.scanResultDal.SearchSoftware(ctx, store.SearchImageScanResultParam{ImageID: imageID, Flag: util.SetBit1(uint64(0), model.FlagHasExceptLicense)}, filter)
	if err != nil {
		return nil, err
	}

	_, webshellCnt, err := s.webshellDal.SearchWebshellImage(ctx, store.SearchWebshellParam{ImageID: imageID}, model.Filter{})
	if err != nil {
		return nil, err
	}
	res = &model.SecurityIssueOverview{
		VULN:           vulnCnt,
		VIRUS:          virusCnt,
		SENSITIVE:      sensitiveCnt,
		Webshell:       webshellCnt,
		Envs:           envCnt,
		Software:       softCnt,
		License:        licenseCnt,
		PrivilegedBoot: 0,
	}
	if image.ConfigFile != nil && (image.ConfigFile.Config.User == consts.BootRootUser || image.ConfigFile.Config.User == "") {
		res.PrivilegedBoot += 1
	}
	return res, nil
}

func (s *ImageSrv) ImageBaseDetail(ctx context.Context, imageID int64) (*model.ImageBaseResponse, error) {
	images, _, err := s.ListImageWithScanInfo(ctx, model.ImageListParam{ImageIds: []int64{imageID}}, nil)
	if err != nil {
		return nil, err
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("not find image:%d", imageID)
	}
	image := images[0]
	// search vulns
	vulns, _, err := s.vulnDal.SearchVuln(ctx, store.SearchVulnParam{ImageIds: []int64{imageID}}, nil)
	if err != nil {
		return nil, err
	}
	// search sensitive file

	sensitive, _, err := s.scanResultDal.SearchSensitive(ctx, store.SearchImageScanResultParam{ImageID: imageID}, nil)
	if err != nil {
		return nil, err
	}

	ans := &model.ImageBaseResponse{
		ID:                     image.ID,
		Digest:                 image.Digest,
		Online:                 image.Online,
		SecurityIssue:          image.SecurityIssue,
		ImageAttr:              image.ImageAttr,
		UUID:                   image.UUID,
		LastScanAt:             image.LastScanAt,
		FullRepoName:           image.FullRepoName,
		Tag:                    image.Tag,
		Os:                     image.Os,
		Size:                   image.Size,
		Flag:                   image.Flag,
		LastSyncAt:             image.LastSyncAt,
		Maintained:             !util.ExistBit1(image.Flag, model.FlagImageNotMaintained),
		BootUser:               image.BootUser,
		VulnFixSuggestion:      make([]string, 0),
		RegistryUrl:            image.RegistryUrl,
		SensitiveFixSuggestion: make([]string, 0),
		RiskScore:              image.RiskScore,
	}

	ans.SensitiveFixSuggestion = utils.GenSensitiveFileSuggest(sensitive)
	ans.VulnFixSuggestion = utils.GenVulnSuggest(ans.Os, vulns)

	return ans, nil
}

func (s *ImageSrv) ListImageWithScanInfo(ctx context.Context, param model.ImageListParam,
	filter *model.Filter) ([]*model.ImageListResponse, int64, error) {
	res := make([]*model.ImageListResponse, 0)

	param.Deserialize()
	if err := param.Valid(); err != nil {
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, err)
	}
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
		OmitFields:   []string{"manifest_v1_json", "manifest_v2_json"},
		UUIDs:        param.UUIDs,
		Fields:       param.Fields,
		StartID:      param.StartID,
	}
	inIds, notInIds := make([]int64, 0), make([]int64, 0)
	onlineIds := make([]int64, 0)
	onlineMap := make(map[int64]bool)
	// 查在线
	onlineSQL := fmt.Sprintf("select  distinct a.id  from  %s a  join %s b  where  a.image_uuid = b.image_uuid  and b.status = 0 ",
		model.ImageList{}.TableName(), model.TensorContainer{}.TableName())

	if len(param.ImageIds) > 0 {
		onlineSQL = fmt.Sprintf("%s and a.id IN (%s)", onlineSQL, util.JoinInt64Slice(param.ImageIds, ","))
	}

	online, err := s.dbdal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSQL})
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.GetOnlineImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	for i := range online {
		onlineIds = append(onlineIds, online[i].ID)
		onlineMap[online[i].ID] = true
	}
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
			LastSyncAt:    images[i].LastFullSyncAt, // 前端要求毫秒时间戳
			Registry:      regMap[images[i].RegistryID],
			UniqueImage:   images[i].UniqueImage,
			Size:          util.ByteToMB(images[i].Size),
		}
		if images[i].ConfigFile != nil {
			ans.BootUser = images[i].ConfigFile.Config.User // fixme 应该在数据表把bootUser单独存一列，优化镜像同步时再做
			if ans.BootUser == "" {
				ans.BootUser = consts.BootRootUser
			}
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

package component

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageSrvInterface interface {
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageBaseResponse, int64, error)
	CreateScanImageTask(ctx context.Context, param model.ImageListParam, taskInfo task.UpdateTaskInfo) error
	GetRegistryProject(ctx context.Context, param GetRegistryProjectParam) ([]RegistryRepo, error)
	UpdateImage(ctx context.Context, where string, updater map[string]interface{}) error
	// 查询很重的接口，慎重传参
	GetImageCorrelateData(ctx context.Context, param model.GetImageAssociateDataParam) (*model.ImageWithCorrelateData, error)
	// 持续更新镜像的flag
	ContinueUpdateImage(ctx context.Context) error
}

func (s *ImageSrv) ContinueUpdateImage(ctx context.Context) error {
	// 已删除的仓库
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("deleteImageAfterDeleteRegistry")
			}
		}()

		s.deleteImageAfterDeleteRegistry(ctx)
	}()

	// 可信镜像flag更新
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("updateTrustedImage")
			}
		}()

		s.updateTrustedImage(ctx)
	}()
	// 在线镜像更新
	return nil
}

func (s *ImageSrv) UpdateImage(ctx context.Context, where string, updater map[string]interface{}) error {
	if where == "" {
		return fmt.Errorf("no where condition")
	}
	if len(updater) == 0 {
		return fmt.Errorf("no update data")
	}
	err := s.imageDal.UpdateImage(ctx, where, updater, nil)
	if err != nil {
		logging.Get().Err(err).Str("where", where).Interface("updater", updater).Msg("UpdateImage")
		return err
	}
	return nil
}

func (s *ImageSrv) ListImageWithScanInfo(ctx context.Context, param model.ImageListParam,
	filter *model.Filter) ([]*model.ImageBaseResponse, int64, error) {
	res := make([]*model.ImageBaseResponse, 0)

	param.Deserialize()

	logging.Get().Info().Interface("param", param).Msg("ListImageWithScanInfo")

	projects := make([]store.RegProject, 0)
	for i := range param.Repos {
		projects = append(projects, store.RegProject{
			RegistryID: param.Repos[i].RegistryID,
			Project:    param.Repos[i].RepoName,
		})
	}

	daoParam := store.SearchImageParam{
		Projects:     projects,
		Keyword:      param.Keyword,
		NodeHostname: param.NodeHostname,
		OmitFields:   []string{"manifest_v1_json", "manifest_v2_json"},
		UUIDs:        param.UUIDs,
		Fields:       param.Fields,
		StartID:      param.StartID,
	}

	if daoParam.StartID > 0 && filter != nil {
		filter.Offset = 0
	}

	daoParam.InIds = param.ImageIds
	daoParam.AttrFlag = param.GenAttrFlag()
	daoParam.SecurityIssueFlag = param.GenSecurityIssueFlag()
	daoParam.AttrIntersection = param.AttrIntersection
	daoParam.IssueIntersection = param.IssueIntersection
	daoParam.ScanStatusFlag = param.ScanStatusFlag
	daoParam.TrustedImage = param.ImageAttr.Trusted
	daoParam.OnlineImage = param.Online

	logging.Get().Info().Interface("daoParam", daoParam).Interface("filter", filter).Msg("SearchImageWithScan.SearchImage")

	images, cnt, err := s.imageDal.SearchImage(ctx, daoParam, filter)
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.SearchImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	if len(images) == 0 {
		return res, 0, nil
	}
	if param.JustReturnImage {
		for i := range images {
			image := images[i]
			base := image.ToImageBaseResponse()
			res = append(res, &base)
		}
		return res, cnt, nil
	}

	uuids, digests := make([]uint32, 0), make([]string, 0)
	onlineMap, trustedMap := make(map[uint32]bool), make(map[string]bool)

	// 转换数据
	for i := range images {
		image := images[i]
		uuids = append(uuids, images[i].ImageUUID)
		digests = append(digests, images[i].Digest)

		// 其他数据
		data, err := s.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
			ImageId:        image.ID,
			EnvEnable:      true,
			SoftwareEnable: true,
			SubtaskEnable:  true,
			RegistryEnable: true,
		})
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.GetImageCorrelateData")
			return nil, 0, err
		}

		baseImageInfo := data.ImageBaseResponse
		res = append(res, &baseImageInfo)
	}

	if !param.NotIdentifyOnline && param.Online == "" {
		resources, err := s.resourceDal.SearchResources(ctx, uuids)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImages.SearchResources")
		} else {
			for i := range resources {
				onlineMap[resources[i].ImageUUID] = true
			}
		}
	}

	if !param.NotIdentifyTrusted && param.ImageAttr.Trusted == "" {
		trustedImages, err := s.trustedImageDal.SearchTrustedImage(ctx, store.SearchTrustedImageParam{IsTrusted: consts.TrueString, Digests: digests})
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchQuestionInfo")
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		for i := range trustedImages {
			trustedMap[trustedImages[i].Digest] = true
		}
	}

	// 转换数据
	for i := range res {
		if param.Online == consts.TrueString {
			res[i].Online = true
		} else if param.Online == consts.FalseString {
			res[i].Online = false
		} else {
			res[i].Online = onlineMap[res[i].UUID]
		}

		if param.ImageAttr.Trusted == consts.TrueString {
			res[i].ImageAttr.Trusted = true
		} else if param.ImageAttr.Trusted == consts.FalseString {
			res[i].ImageAttr.Trusted = false
		} else {
			res[i].ImageAttr.Trusted = trustedMap[res[i].Digest]
		}
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
	repos, err := s.imageDal.GroupRegistryProject(ctx, store.GroupRegistryRepoParam{ProjectKeyword: param.ProjectKeyword, RegID: param.RegID})
	if err != nil {
		logging.Get().Err(err).Msg("GetRegistryProject.GroupRegistryProject")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	resMap := make(map[int64][]store.RegProject)
	for i := range repos {
		repos[i].Name = repos[i].Project
	}
	// 查出所有的registry
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{Deleted: consts.FalseString}, nil)
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

func (s *ImageSrv) GetImageCorrelateData(ctx context.Context, param model.GetImageAssociateDataParam) (*model.ImageWithCorrelateData, error) {
	// base image info
	if err := param.Valid(); err != nil {
		return nil, err
	}
	param.Deserialize()

	ans := &model.ImageWithCorrelateData{}

	images, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{InIds: []int64{param.ImageId}}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("ImageID", param.ImageId).Msg("ImageWithCorrelateData ImageBaseDetail")
		return nil, err
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("not find image:%d", param.ImageId)
	}
	image := images[0]

	ans.ImageList = image

	imageID := param.ImageId

	registry, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{Deleted: consts.FalseString, ID: image.RegistryID}, nil)
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.SearchRegistry")
		return nil, err
	}
	if len(registry) > 0 {
		ans.Registry = &(registry[0])
	}

	daoParam := ScanResultParamToStoreParam(param.ScanResultSearchParam)

	daoParam.ImageID = imageID

	versionThan211 := s.versionThan211(ans.ImageList)
	logging.Get().Info().Bool("versionThan211", versionThan211).Msg("GetImageCorrelateData")

	if !versionThan211 && (param.EnvEnable || param.VirusEnable || param.SensitiveEnable || param.SoftwareEnable || param.LicenseEnable) {
		dataFor211, err := s.GetImageCorrelateDataFor211(ctx, param)
		if err != nil {
			logging.Get().Err(err).Int64("imageID", param.ImageId).Msg("GetImageCorrelateData GetImageCorrelateDataFor211")
			return nil, err
		}

		ans.VirusCnt = dataFor211.VirusCnt
		ans.Virus = dataFor211.Virus
		ans.SensitiveCnt = dataFor211.SensitiveCnt
		ans.Sensitive = dataFor211.Sensitive
		ans.EnvCnt = dataFor211.EnvCnt
		ans.Env = dataFor211.Env
		ans.License = dataFor211.License
		ans.Software = dataFor211.Software
		ans.SoftwareCnt = dataFor211.SoftwareCnt
	}

	if versionThan211 {
		// env
		if param.EnvEnable {
			env, cnt, err := s.scanResultDal.SearchImageEnv(ctx, daoParam, nil)
			if err != nil {
				logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchImageEnv")
				return nil, err
			}
			ans.Env = env
			ans.EnvCnt = cnt
		}

		if param.SensitiveEnable {
			sensitive, cnt, err := s.scanResultDal.SearchSensitive(ctx, daoParam, nil)
			if err != nil {
				logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchSensitive")
				return nil, err
			}
			ans.Sensitive = sensitive
			ans.SensitiveCnt = cnt
		}

		if param.SoftwareEnable {
			software, cnt, err := s.scanResultDal.SearchSoftware(ctx, daoParam, nil)
			if err != nil {
				logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchSoftware")
				return nil, err
			}
			ans.Software = software
			ans.SoftwareCnt = cnt
		}
		if param.LicenseEnable {
			software, _, err := s.scanResultDal.SearchSoftware(ctx, daoParam, nil)
			if err != nil {
				return nil, err
			}
			for i := range software {
				if software[i].License != "" {
					ans.License = append(ans.License, software[i].License)
				}
			}
			ans.License = util.DeDuplicationStringSlice(ans.License)
		}

		if param.VirusEnable {
			virus, cnt, err := s.scanResultDal.SearchVirus(ctx, daoParam, param.Filter)
			if err != nil {
				logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchVirus")
				return nil, err
			}
			ans.Virus = virus
			ans.VirusCnt = cnt
		}

		if param.WebshellEnable {
			webshell, webshellCnt, err := s.scanResultDal.SearchWebShell(ctx, daoParam, nil)
			if err != nil {
				logging.Get().Err(err).Msg("SearchImageWithScan.SearchWebShell")
				return nil, err
			}
			ans.WebshellCnt = webshellCnt
			ans.Webshell = webshell
		}
	}

	// 查询该镜像的所有漏洞，更详细的查询请使用VulnServiceInterface
	if param.VulnEnable {
		vuln, cnt, err := s.vulnDal.SearchVuln(ctx, store.SearchVulnParam{ImageIds: []int64{imageID},
			OmitFields: param.ScanResultSearchParam.OmitFields}, nil)
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchVuln")
			return nil, err
		}
		ans.Vuln = vuln
		ans.VulnCnt = cnt
	}

	// lastScanTask
	if param.SubtaskEnable {
		subtasks, cnt, err := s.scanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{ImageID: imageID},
			model.EmptyFilter().AddSortDesc().AddSortFiledByID().AddLimit(1))
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchSubTasksWithStatusFilter")
			return nil, err
		}
		ans.SubTask = subtasks
		ans.SubTaskCnt = cnt
	}

	// container
	if param.ContainerEnable {
		resources, err := s.resourceDal.SearchResources(ctx, []uint32{image.ImageUUID})
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchResources")
			return nil, err
		}
		ans.Container = resources
	}

	if param.AppImageEnable && util.ExistBit1(image.Flag, model.FlagBaseImage) {
		base, cnt, err := s.ListAppImageOfBase(ctx, model.ImageListParam{ImageIds: []int64{image.ID}, Keyword: param.ScanResultSearchParam.Keyword}, nil)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.ListAppImageOfBase")
			return nil, err
		}
		ans.BaseImages = base
		ans.BaseImageCnt = cnt
	}

	if param.BaseImageEnable && !util.ExistBit1(image.Flag, model.FlagBaseImage) {
		apps, cnt, err := s.ListBaseImageOfApp(ctx, model.ImageListParam{ImageIds: []int64{image.ID}, Keyword: param.ScanResultSearchParam.Keyword}, nil)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchResources")
			return nil, err
		}
		ans.AppImages = apps
		ans.AppImageCnt = cnt
	}

	ans.ImageBaseResponse = ans.ToImageBaseResponse()
	// 程序中分页
	ans = ans.AddFilter(param.Filter)
	return ans, nil
}

// 获取应用镜像的基础镜像列表
func (s *ImageSrv) ListBaseImageOfApp(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageBaseResponse, int64, error) {
	if len(param.ImageIds) == 0 {
		return nil, 0, fmt.Errorf("not get imageID")
	}

	images, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{
		InIds:  param.ImageIds,
		Fields: []string{"id", "flag", "layers"}}, nil)
	if err != nil {
		logging.Get().Err(err).Msg("SearchImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取基础镜像出错"))
	}
	if len(images) == 0 || model.ExistFlag(images[0].Flag, model.FlagBaseImage) {
		return nil, 0, nil
	}
	// 先获取所有基础镜像
	baseImages, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{
		AttrFlag: util.SetBit1(0, model.FlagBaseImage),
		Keyword:  param.Keyword,
		NotInIds: []int64{images[0].ID}},
		model.EmptyFilterForTotalQuery())
	if err != nil {
		logging.Get().Err(err).Msg("ListBaseImageOfApp")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("ListBaseImageOfApp"))
	}

	baseImageMap := make(map[int64]model.ImageList)
	for i := range baseImages {
		baseImageMap[baseImages[i].ID] = baseImages[i]
	}
	baseImageIds := make([]int64, 0)
	for i := range baseImages {
		if strings.HasPrefix(images[0].Layers, baseImages[i].Layers) {
			baseImageIds = append(baseImageIds, baseImages[i].ID)
		}
	}
	cnt := int64(len(baseImageIds))

	// 应付前端分页
	if filter != nil && len(baseImageIds) > 0 {
		start := int(filter.Offset)
		end := int(filter.Offset + filter.Limit)

		if len(baseImageIds) <= start {
			return make([]*model.ImageBaseResponse, 0), int64(len(baseImages)), nil
		}
		if end > len(baseImageIds) {
			end = len(baseImageIds)
		}
		baseImageIds = baseImageIds[start:end]
	}

	baseInfo, _, err := s.ListImageWithScanInfo(ctx, model.ImageListParam{ImageIds: baseImageIds}, model.EmptyFilterForTotalQuery())
	if err != nil {
		logging.Get().Err(err).Msg("ListBaseImageOfApp")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("ListBaseImageOfApp"))
	}
	return baseInfo, cnt, nil
}

// 获取基础镜像的应用的镜像列表
func (s *ImageSrv) ListAppImageOfBase(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageBaseResponse, int64, error) {

	if len(param.ImageIds) == 0 {
		return nil, 0, fmt.Errorf("not get imageID")
	}

	images, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{InIds: param.ImageIds,
		Fields: []string{"id", "flag", "layers"}}, nil)
	if err != nil {
		logging.Get().Err(err).Msg("ListAppImageOfBase")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取基础镜像出错"))
	}
	if len(images) == 0 || !model.ExistFlag(images[0].Flag, model.FlagBaseImage) {
		return nil, 0, nil
	}

	appImage, cnt, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{
		LayersPrefix: images[0].Layers, NotInIds: []int64{images[0].ID},
		Fields: []string{"id", "flag", "layers"}}, filter)
	if err != nil {
		logging.Get().Err(err).Msg("ListAppImageOfBase")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("ListAppImageOfBase"))
	}
	appImageIds := make([]int64, 0)
	for i := range appImage {
		appImageIds = append(appImageIds, appImage[i].ID)
	}
	if len(appImageIds) == 0 {
		return make([]*model.ImageBaseResponse, 0), cnt, nil
	}

	appInfo, _, err := s.ListImageWithScanInfo(ctx, model.ImageListParam{ImageIds: appImageIds}, model.EmptyFilterForTotalQuery())
	if err != nil {
		logging.Get().Err(err).Msg("ListBaseImageOfApp")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("ListBaseImageOfApp"))
	}
	return appInfo, cnt, nil
}

// 2.11版本，数据没有拆分,兼容老数据
func (s *ImageSrv) GetImageCorrelateDataFor211(ctx context.Context, param model.GetImageAssociateDataParam) (*model.ImageWithCorrelateData, error) {
	imageData, err := s.scanResultDal.SearchScanImage(ctx, param.ScanResultSearchParam)
	if err != nil {
		logging.Get().Err(err).Int64("imageID", param.ImageId).Msg("GetImageCorrelateDataFor211 SearchScanImage")
		return nil, err
	}
	if !param.SoftwareEnable || param.ScanResultSearchParam.AbnormalSoft == consts.TrueString {
		return imageData, nil
	}
	abnormalSoft := make(map[string]uint64)
	for i := range imageData.Software {
		key := fmt.Sprintf("%s|%s", imageData.Software[i].Name, imageData.Software[i].Version)
		abnormalSoft[key] = imageData.Software[i].Flag
	}

	// 查software
	vulns, _, err := s.vulnDal.SearchVuln(ctx, store.SearchVulnParam{
		Fields:   []string{"id", "name", "pkg_name", "pkg_version"},
		ImageIds: []int64{param.ImageId},
	}, nil)

	if err != nil {
		logging.Get().Err(err).Int64("imageID", param.ImageId).Msg("GetImageCorrelateDataFor211 SearchVuln")
		return nil, err
	}

	softExit := make(map[string]bool)
	soft := make([]*model.ImageSoftware, 0)
	keyword := param.ScanResultSearchParam.Keyword
	for i := range vulns {
		key := fmt.Sprintf("%s|%s", vulns[i].PkgName, vulns[i].PkgVersion)
		if !softExit[key] {
			softExit[key] = true

			if keyword != "" && (!strings.Contains(strings.ToLower(vulns[i].PkgName), keyword) &&
				!strings.Contains(strings.ToLower(vulns[i].PkgVersion), keyword)) {
				continue
			}

			so := &model.ImageSoftware{
				Name:    vulns[i].PkgName,
				Version: vulns[i].PkgVersion,
				Flag:    abnormalSoft[key],
			}

			soft = append(soft, so)
		}
	}

	imageData.Software = soft
	imageData.SoftwareCnt = int64(len(soft))

	return imageData, nil
}

func (s *ImageSrv) deleteImageAfterDeleteRegistry(ctx context.Context) {
	regChan := s.getDeleteRegistry(ctx)

	for reg := range regChan {
		var startID int64
		filter := model.EmptyFilter().AddLimit(consts.DefaultLimit).AddSortAsc().AddSortFiledByID()
		for {
			images, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{RegistryIds: []int64{reg.ID},
				Fields: []string{"id"}, StartID: startID}, filter)
			if err != nil {
				break
			}
			if len(images) == 0 {
				break
			}
			startID = images[len(images)-1].ID

			for i := range images {
				if err := s.imageDal.DeleteImage(ctx, images[i].ID); err != nil {
					continue
				}
			}
		}
	}
}

func (s *ImageSrv) updateTrustedImage(ctx context.Context) {
	regChan := s.getTrustImage(ctx)

	for reg := range regChan {
		var startID int64
		filter := model.EmptyFilter().AddLimit(consts.DefaultLimit).AddSortAsc().AddSortFiledByID()
		for {
			images, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{Digests: []string{reg.Digest},
				Fields: []string{"id", "flag"}, StartID: startID}, filter)
			if err != nil {
				break
			}
			if len(images) == 0 {
				break
			}
			startID = images[len(images)-1].ID

			for i := range images {
				if util.ExistBit1(images[i].Flag, model.FlagImageTrusted) {
					continue
				}

				updater := map[string]interface{}{"flag": util.SetBit1(images[i].Flag, model.FlagImageTrusted)}
				if err := s.UpdateImage(ctx, fmt.Sprintf("id = %d", images[i].ID), updater); err != nil {
					continue
				}
			}
		}
	}
}

func (s *ImageSrv) getDeleteRegistry(ctx context.Context) chan model.Registry {
	out := make(chan model.Registry)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("getDeleteRegistry")
			}
		}()

		defer close(out)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		// 对于镜像检测，前10分钟，每一分钟检测一次，10分钟之后，就每5分钟检测一次
		regMap := make(map[int64]int)
		for {
			<-ticker.C
			regs, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{Deleted: consts.TrueString}, nil)
			if err != nil {
				logging.Get().Err(err).Msg("ContinueUpdateImage SearchRegistry")
			}
			for i := range regs {
				if (time.Now().Unix()-regs[i].DeletedAt)/60 <= 10 {
					out <- regs[i]
				} else {
					regMap[regs[i].ID]++
					if regMap[regs[i].ID] == 5 {
						regMap[regs[i].ID] = 0
						out <- regs[i]
					}
				}
			}
		}
	}()
	return out
}

func (s *ImageSrv) getTrustImage(ctx context.Context) chan *model.TrustedImages {
	out := make(chan *model.TrustedImages)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("getDeleteRegistry")
			}
		}()

		defer close(out)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		// 对于镜像检测，前10分钟，每一分钟检测一次，10分钟之后，就每5分钟检测一次
		regMap := make(map[uint]int)
		for {
			<-ticker.C
			regs, err := s.trustedImageDal.SearchTrustedImage(ctx, store.SearchTrustedImageParam{IsTrusted: consts.TrueString})
			if err != nil {
				logging.Get().Err(err).Msg("ContinueUpdateImage SearchTrustedImage")
			}
			for i := range regs {
				if (time.Now().Unix()-regs[i].UpdatedAt.Unix())/60 <= 10 {
					out <- regs[i]
				} else {
					regMap[regs[i].ID]++
					if regMap[regs[i].ID] == 5 {
						regMap[regs[i].ID] = 0
						out <- regs[i]
					}
				}
			}
		}
	}()
	return out
}

func (s *ImageSrv) versionThan211(im model.ImageList) bool {
	regID := im.RegistryID
	registries, _, err := s.registryDal.SearchRegistry(context.Background(), store.SearchRegistryParam{ID: regID, Deleted: consts.FalseString}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("regID", regID).Msg("versionThan211 SearchRegistry")
		return true
	}
	if len(registries) == 0 {
		logging.Get().Error().Int64("regID", regID).Msg("versionThan211 SearchRegistry not find registry")
		return true
	}

	scannerInstance, err := s.scannerInfoDal.SearchScannerInfo(context.Background(), store.ScannerInstanceInfoDaoParam{ScannerInstance: registries[0].ScannerInstance})
	if err != nil {
		logging.Get().Err(err).Int64("regID", regID).Msg("versionThan211 SearchScannerInfo")
		return true
	}

	if len(scannerInstance) == 0 {
		logging.Get().Error().Int64("regID", regID).Str("scannerInstance", registries[0].ScannerInstance).Msg("versionThan211 SearchRegistry not find scannerInstance")
		return true
	}

	return util.CompareVersion(scannerInstance[0].ScannerVersion, consts.ScannerVersion211) > 0
}

type ImageSrv struct {
	imageDal        store.ImageDal
	scanTaskDal     store.ScanTaskInterface
	registryDal     store.RegistryDal
	webshellDal     store.WebshellDal
	vulnDal         store.VulnDalInterface
	scanResultDal   store.ImageScanResultDal
	trustedImageDal store.TrustedImageDal
	resourceDal     store.ResourceDal
	scannerInfoDal  store.ScannerInstanceInfoDal
}

func NewImageSrv(
	imageDal store.ImageDal,
	registryDal store.RegistryDal,
	scanTaskDal store.ScanTaskInterface,
	vulnDal store.VulnDalInterface,
	scanResultDal store.ImageScanResultDal,
	webshellDal store.WebshellDal,
	trustedImageDal store.TrustedImageDal,
	resourceDal store.ResourceDal,
	scannerInfoDal store.ScannerInstanceInfoDal,
) *ImageSrv {
	return &ImageSrv{
		imageDal:        imageDal,
		scanTaskDal:     scanTaskDal,
		registryDal:     registryDal,
		vulnDal:         vulnDal,
		scanResultDal:   scanResultDal,
		webshellDal:     webshellDal,
		trustedImageDal: trustedImageDal,
		resourceDal:     resourceDal,
		scannerInfoDal:  scannerInfoDal,
	}
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

func ScanResultParamToStoreParam(s model.ScanResultSearchParam) store.SearchImageScanResultParam {
	param := store.SearchImageScanResultParam{
		ImageID:     s.ImageID,
		LayerDigest: s.LayerDigest,
		Keyword:     s.Keyword,
	}
	if s.AbnormalLicense == consts.TrueString {
		param.Flag = util.SetBit1(param.Flag, model.FlagHasExceptLicense)
	}

	if s.AbnormalEnv == consts.TrueString {
		param.NormalEnv = consts.FalseString
	} else if s.AbnormalEnv == consts.FalseString {
		param.NormalEnv = consts.TrueString
	}

	if s.AbnormalSoft == consts.TrueString {
		param.Flag = util.SetBit1(param.Flag, model.FlagHasSoftware)
	}
	return param
}

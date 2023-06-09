package imagemeta

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageService interface {
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageListParam) ([]*imagesecModel.ImageBaseResponse, int64, error)
	CreateScanImageTask(ctx context.Context, param imagesecModel.ImageListParam, taskInfo task.UpdateTaskInfo) error
	SearchProject(ctx context.Context, param imagesecModel.SearchProjectParam) ([]imagesecModel.GroupProjectResponse, error)
	UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error
	// 查询很重的接口，慎重传参
	GetImageCorrelateData(ctx context.Context, param imagesecModel.GetImageAssociateDataParam) (*imagesecModel.ImageWithCorrelateData2, error)
	// 持续更新镜像的flag
	ContinueUpdateDeleteImage(ctx context.Context) error
}

type NodeImageSrv struct {
	imageDal        imagesecStore.ImageMetaDal
	registryDal     store.RegistryDal
	scanResultDal   imagesecStore.ScanResultDal
	resourceDal     store.ResourceDal
	nodeReportDal   imagesecStore.NodeInfoDal
	policyDal       imagesecStore.DetectPolicyDal
	detectResultDal imagesecStore.ImageDetectResultDal
	trustedDal      store.TrustedImageDal
	configDal       imagesecStore.ScanImageConfigDal
	nodeTaskDal     imagesecStore.ScanTaskDal
	redisCli        *redis.Client
}

func NewNodeImageSrv(
	imageDal imagesecStore.ImageMetaDal,
	registryDal store.RegistryDal,
	scanResultDal imagesecStore.ScanResultDal,
	resourceDal store.ResourceDal,
	nodeReportDal imagesecStore.NodeInfoDal,
	policyDal imagesecStore.DetectPolicyDal,
	detectResultDal imagesecStore.ImageDetectResultDal,
	trustedDal store.TrustedImageDal,
	configDal imagesecStore.ScanImageConfigDal,
	nodeTaskDal imagesecStore.ScanTaskDal,
) *NodeImageSrv {
	srv := NodeImageSrv{
		imageDal:        imageDal,
		registryDal:     registryDal,
		scanResultDal:   scanResultDal,
		resourceDal:     resourceDal,
		nodeReportDal:   nodeReportDal,
		policyDal:       policyDal,
		detectResultDal: detectResultDal,
		trustedDal:      trustedDal,
		configDal:       configDal,
		nodeTaskDal:     nodeTaskDal,
	}
	return &srv
}

func (s *NodeImageSrv) ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageListParam) (
	[]*imagesecModel.ImageBaseResponse, int64, error) {

	res := make([]*imagesecModel.ImageBaseResponse, 0)

	param.Deserialize()

	logging.Get().Debug().Interface("param", param).Msg("ListImageWithScanInfo")

	daoParam := imagesecModel.NodeImageDalParam{
		ImageFromType: param.ImageFromType,
		Projects:      param.Repos,
		ImageKeyword:  param.ImageKeyword,
		NodeKeyword:   param.NodeKeyword,
		UUIDs:         param.UUIDs,
		UniqueIds:     param.UniqueIds,
		Fields:        param.Fields,
		StartID:       param.StartID,
		ClusterKey:    param.ClusterKey,
		InIds:         param.ImageIds,
		WebshellMD5:   param.WebshellMD5,
		Filter:        param.Filter,
	}

	if daoParam.StartID > 0 && param.Filter != nil {
		param.Filter.Offset = 0
	}

	daoParam.OrFlag |= param.SafeAttrFlag
	daoParam.OrFlag |= param.OnlineFlag

	if param.AttrIntersection == model.AndString {
		daoParam.AndFlag |= param.ImageAttrFlag
	}
	if param.IssueIntersection == model.AndString {
		daoParam.AndFlag |= param.SecurityIssueFlag
	}
	if param.VulnStaticIntersection == model.AndString {
		daoParam.AndFlag |= param.VulnStaticFlag
	}

	if param.AttrIntersection == model.OrString {
		daoParam.OrFlag |= param.ImageAttrFlag
	}
	if param.IssueIntersection == model.OrString {
		daoParam.OrFlag |= param.SecurityIssueFlag
	}
	if param.VulnStaticIntersection == model.OrString {
		daoParam.OrFlag |= param.VulnStaticFlag
	}

	daoParam.Fields = []string{"id", "unique_id"}

	logging.Get().Debug().Interface("daoParam", daoParam).Interface("filter", param.Filter).Msg("SearchImageWithScan.SearchImage")

	images, cnt, err := s.imageDal.SearchImage(ctx, daoParam)
	if err != nil {
		logging.Get().Err(err).Msg("SearchImageWithScan.SearchImage")
		return nil, 0, err
	}

	if len(images) == 0 {
		return res, 0, nil
	}

	// 转换数据
	for i := range images {
		assParam := imagesecModel.GetImageAssociateDataParam{
			ImageFromType:      param.ImageFromType,
			ImageId:            images[i].ID,
			SubtaskEnable:      true,
			VulnEnable:         true,
			NodeInfoEnable:     true,
			RiskPolicyEnable:   true,
			DetectResultEnable: true,
		}

		// 其他数据
		data, err := s.GetImageCorrelateData(ctx, assParam)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.GetImageCorrelateData")
			return nil, 0, err
		}
		baseImageInfo := data.ToImageBaseResponse()
		res = append(res, &baseImageInfo)
	}

	return res, cnt, nil
}

func (s *NodeImageSrv) CreateScanImageTask(ctx context.Context, param imagesecModel.ImageListParam,
	taskInfo task.UpdateTaskInfo) error {
	panic("implement me")
}

func (s *NodeImageSrv) UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error {
	err := s.imageDal.UpdateImage(ctx, param)
	if err != nil {
		logging.Get().Err(err).Interface("param", param).Msg("UpdateImage")
		return err
	}
	return nil
}

func (s *NodeImageSrv) GetImageCorrelateData(ctx context.Context,
	param imagesecModel.GetImageAssociateDataParam) (*imagesecModel.ImageWithCorrelateData2, error) {

	param.Deserialize()

	// 程序中分页
	if param.SearchVulnParam.Filter != nil {
		param.SearchVulnParam.Filter = param.SearchVulnParam.Filter.SetLimit(0).SetOffset(0)
	}
	if param.ScanResultSearchParam.Filter != nil {
		param.ScanResultSearchParam.Filter = param.ScanResultSearchParam.Filter.SetLimit(0).SetOffset(0)
	}

	if err := param.Check(); err != nil {
		return nil, err
	}

	ans := &imagesecModel.ImageWithCorrelateData2{
		RiskPolicy:  make([]*imagesecModel.SecurityPolicy, 0),
		TotalPolicy: make([]*imagesecModel.SecurityPolicy, 0),
	}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
		ImageID: param.ImageId, UniqueId: param.ImageUniqueID})
	if err != nil {
		logging.Get().Err(err).Int64("ImageID", param.ImageId).Msg("ImageWithCorrelateData ImageBaseDetail")
		return nil, err
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("image not found, possible reason is the image has been cleaned")
	}
	image := images[0]
	ans.Image = *image
	imageID, imageUniqueID := image.ID, image.UniqueID

	param.ScanResultSearchParam.ImageUniqueID = imageUniqueID
	if param.ImageFromType == imagesecModel.ImageFromRegistry && param.RegistryEnable {
		registry, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{Deleted: consts.FalseString, ID: image.RegID}, nil)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchRegistry")
			return nil, err
		}
		if len(registry) > 0 {
			ans.Registry = &(registry[0])
		}
	}
	// env
	if param.EnvEnable {
		env, cnt, err := s.scanResultDal.SearchImageEnv(ctx, param.ScanResultSearchParam)
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", image.ID).Msg("ImageWithCorrelateData SearchImageEnv")
			return nil, err
		}

		ans.Env = env
		ans.EnvCnt = cnt
	}

	if param.SensitiveEnable {
		sensitive, cnt, err := s.scanResultDal.SearchSensitive(ctx, param.ScanResultSearchParam)
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchSensitive")
			return nil, err
		}
		ans.Sensitive = sensitive
		ans.SensitiveCnt = cnt
	}

	if param.PkgEnable {
		pkg, cnt, err := s.scanResultDal.SearchPkg(ctx, param.ScanResultSearchParam)
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchPkg")
			return nil, err
		}
		ans.Pkg = pkg
		ans.PkgCnt = cnt
	}
	if param.LicenseEnable {
		software, _, err := s.scanResultDal.SearchPkg(ctx, param.ScanResultSearchParam)
		if err != nil {
			return nil, err
		}
		for i := range software {
			ans.License = append(ans.License, software[i].License...)
		}
		ans.License = util.DuplicateStringSlice(ans.License)
	}

	if param.MalwareEnable {
		virus, cnt, err := s.scanResultDal.SearchMalware(ctx, param.ScanResultSearchParam)
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchVirus")
			return nil, err
		}
		ans.Malware = virus
		ans.MalwareCnt = cnt
	}

	if param.WebshellEnable {
		webshell, webshellCnt, err := s.scanResultDal.SearchWebshell(ctx, param.ScanResultSearchParam)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchWebshell")
			return nil, err
		}
		ans.WebshellCnt = webshellCnt

		ans.Webshell = make([]*imagesecModel.WebshellView, len(webshell))
		for i := range webshell {
			ans.Webshell[i] = webshell[i].ToWebshellView()
		}
	}
	// 查询该镜像的所有漏洞
	if param.VulnEnable {
		param.SearchVulnParam.ImageUniqueID = imageUniqueID
		vuln, cnt, err := s.scanResultDal.SearchVuln(ctx, param.SearchVulnParam)
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchVuln")
			return nil, err
		}
		vulns := make([]*imagesecModel.VulnView, len(vuln))
		for i := range vuln {
			vulns[i] = vuln[i].GenVulnView()
		}

		ans.Vuln = vulns
		ans.VulnCnt = cnt
	}

	// lastScanTask
	if param.SubtaskEnable {
		subtasks, cnt, err := s.nodeTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			ImageUniqueID: imageUniqueID, ScanStatus: []int64{imagesecModel.TaskStatusDetectFinished},
			Filter: model.EmptyFilter().SetSortDesc().SetSortFiledByID().SetLimit(1)})

		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchSubTasksWithStatusFilter")
			return nil, err
		}
		ans.ScanSubTask = subtasks
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
	// 获取应用镜像列表
	if param.AppImageEnable && util.ExistBit1(image.Flag, model.FlagBaseImage) {
		appImageParam := imagesecModel.ImageListParam{ImageIds: []int64{image.ID}, ImageKeyword: param.ScanResultSearchParam.Keyword,
			ImageFromType: param.ImageFromType}
		appImages, appImageCnt, err := s.ListAppImageOfBase(ctx, appImageParam)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.ListAppImageOfBase")
			return nil, err
		}
		ans.AppImages = appImages
		ans.AppImageCnt = appImageCnt
	}

	if param.BaseImageEnable && !util.ExistBit1(image.Flag, model.FlagBaseImage) {
		baseImageParam := imagesecModel.ImageListParam{ImageIds: []int64{image.ID}, ImageKeyword: param.ScanResultSearchParam.Keyword,
			ImageFromType: param.ImageFromType}
		baseImages, baseImageCnt, err := s.ListBaseImageOfApp(ctx, baseImageParam)
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchResources")
			return nil, err
		}
		ans.BaseImages = baseImages
		ans.BaseImageCnt = baseImageCnt
	}
	if param.NodeInfoEnable {
		nodes, _, err := s.nodeReportDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{UniqueIds: []uint64{image.NodeID}})
		if err != nil {
			logging.Get().Err(err).Msg("SearchImageWithScan.SearchNodeInfo")
			return nil, err
		}
		if len(nodes) > 0 {
			cluster, err := s.resourceDal.SearchCluster(ctx, nodes[0].ClusterKey)
			if err != nil {
				logging.Get().Err(err).Msg("SearchImageWithScan.SearchCluster")
				return nil, err
			}
			nodes[0].ClusterName = cluster.Name
			ans.NodeInfo = nodes[0]
		}
	}
	if param.RiskPolicyEnable {
		policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Deleted: consts.FalseString})
		if err != nil {
			logging.Get().Err(err).Msg("SearchDetectPolicy")
			return nil, err
		}

		policyIds := make([]int64, 0)
		for i := range policy {
			policyIds = append(policyIds, policy[i].ID)
		}
		if len(policyIds) > 0 {
			brief, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
				ImageUniqueID: imageUniqueID, PolicyIds: policyIds})
			if err != nil {
				logging.Get().Err(err).Int64("imageID", imageID).Msg("SearchDetectBrief")
				return nil, err
			}
			for i := range brief {
				if brief[i].Policy != nil {
					ans.TotalPolicy = append(ans.TotalPolicy, brief[i].Policy)
					if util.ExistBit1(brief[i].Flag, imagesecModel.FlagDetectException) {
						ans.RiskPolicy = append(ans.RiskPolicy, brief[i].Policy)
					}
				}
			}
		}
	}

	if param.DetectResultEnable {
		ans.DetectResult = make(map[string][]*imagesecModel.ImageDetectResult)
		detectTypes := param.GetDetectTypes()
		for dt := range detectTypes {
			result, err := s.detectResultDal.SearchDetectResult(ctx, imagesecModel.SearchDetectResultParam{
				ImageUniqueID: imageUniqueID,
				PolicyIds:     param.ScanResultSearchParam.SecurityPolicyIds,
				DetectType:    detectTypes[dt],
			})
			if err != nil {
				logging.Get().Err(err).Msg("SearchImageWithScan.SearchDetectResult")
				return nil, err
			}
			for i := range result {
				if ans.DetectResult[detectTypes[dt]] == nil {
					ans.DetectResult[detectTypes[dt]] = make([]*imagesecModel.ImageDetectResult, 0)
				}
				ans.DetectResult[detectTypes[dt]] = append(ans.DetectResult[detectTypes[dt]], result[i])
			}
		}
	}

	ans.AddDetectResult()

	ans.ExceptionFilter(param.ScanResultSearchParam)

	ans.ImageBaseResponse = ans.ToImageBaseResponse()
	// 程序中分页
	ans = ans.AddFilter(param.Filter)
	return ans, nil
}

func (s *NodeImageSrv) SearchProject(ctx context.Context, param imagesecModel.SearchProjectParam) (
	[]imagesecModel.GroupProjectResponse, error) {
	if err := param.Check(); err != nil {
		return nil, err
	}
	empty := make([]imagesecModel.GroupProjectResponse, 0)
	switch param.ImageFromType {
	case imagesecModel.ImageFromRegistry:
		return s.groupLibProject(ctx, param)
	case imagesecModel.ImageFromNode:
		return s.groupNodeProject(ctx, param)
	default:
		return empty, nil
	}
}

func (s *NodeImageSrv) ContinueUpdateDeleteImage(ctx context.Context) error {
	return nil
}

// 获取应用镜像的基础镜像列表
func (s *NodeImageSrv) ListBaseImageOfApp(ctx context.Context, param imagesecModel.ImageListParam) (
	[]*imagesecModel.ImageBaseResponse, int64, error) {
	empty := make([]*imagesecModel.ImageBaseResponse, 0)

	return empty, 0, nil
}

// 获取基础镜像的应用的镜像列表
func (s *NodeImageSrv) ListAppImageOfBase(ctx context.Context, param imagesecModel.ImageListParam) (
	[]*imagesecModel.ImageBaseResponse, int64, error) {

	empty := make([]*imagesecModel.ImageBaseResponse, 0)

	return empty, 0, nil
}

func (s *NodeImageSrv) groupLibProject(ctx context.Context, param imagesecModel.SearchProjectParam) (
	[]imagesecModel.GroupProjectResponse, error) {
	param.ImageFromType = imagesecModel.ImageFromRegistry
	repos, err := s.imageDal.SearchProject(ctx, param)
	if err != nil {
		logging.Get().Err(err).Msg("GetRegistryProject.GroupRegistryProject")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	resMap := make(map[int64][]imagesecModel.Project)
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
			resMap[repo.RegistryID] = make([]imagesecModel.Project, 0)
		}
		resMap[repo.RegistryID] = append(resMap[repo.RegistryID], repo)
	}
	res := make([]imagesecModel.GroupProjectResponse, 0)
	for k, v := range resMap {
		res = append(res, imagesecModel.GroupProjectResponse{
			Projects: v,
			Name:     regMap[k].Name,
			Key:      fmt.Sprintf("%d", k),
		})
	}
	return res, nil
}

func (s *NodeImageSrv) groupNodeProject(ctx context.Context, param imagesecModel.SearchProjectParam) (
	[]imagesecModel.GroupProjectResponse, error) {
	param.ImageFromType = imagesecModel.ImageFromNode
	repos, err := s.imageDal.SearchProject(ctx, param)
	if err != nil {
		logging.Get().Err(err).Msg("GetRegistryProject.GroupRegistryProject")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	resMap := make(map[uint64][]imagesecModel.Project)
	for i := range repos {
		repos[i].Name = repos[i].Project
	}
	nodes, _, err := s.nodeReportDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{})
	if err != nil {
		logging.Get().Err(err).Msg("GetRegistryProject.SearchRegistry")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	nodeMap := make(map[uint64]*imagesecModel.NodeInfo)
	for i := range nodes {
		nodeMap[nodes[i].UniqueID] = nodes[i]
	}

	for i := range repos {
		if _, ok := nodeMap[repos[i].NodeUniqueID]; !ok {
			continue
		}
		repo := repos[i]
		repo.Key = fmt.Sprintf("%d,%s", repo.NodeUniqueID, repo.Project)

		if resMap[repo.NodeUniqueID] == nil {
			resMap[repo.NodeUniqueID] = make([]imagesecModel.Project, 0)
		}
		resMap[repo.NodeUniqueID] = append(resMap[repo.NodeUniqueID], repo)
	}
	res := make([]imagesecModel.GroupProjectResponse, 0)
	for k, v := range resMap {
		res = append(res, imagesecModel.GroupProjectResponse{
			Projects: v,
			Name:     nodeMap[k].Hostname,
			Key:      fmt.Sprintf("%d", k),
		})
	}
	return res, nil
}

package imagemeta

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta/metaGlobal"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 获取应用镜像的基础镜像列表
func (s *ImageInfoMetaSrv) ListBaseImageOfApp(ctx context.Context, param imagesecModel.ImageSearchApiParam) (
	[]*imagesecModel.ImageBaseResponse, int64, error) {

	empty := make([]*imagesecModel.ImageBaseResponse, 0)
	if param.UniqueId <= 0 {
		return empty, 0, scani18.NotGetImageID()
	}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
		UniqueId: param.UniqueId,
		Fields:   []string{"id", "flag", "layer_str"}})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("SearchImage")
		return nil, 0, scani18.GetImageInfo(err)
	}
	if len(images) == 0 || !util.ExistBit1(images[0].Flag, imagesecModel.FlagAppImage) || images[0].LayerStr == "" {
		return empty, 0, nil
	}
	appImage := images[0]
	daoParam := imagesecModel.ImageDalParam{
		ImageFromType: param.ImageFromType,
		ImageAttrFlag: util.SetBit1(0, imagesecModel.FlagBaseImage),
		Fields:        []string{"unique_id", "flag", "layer_str", "id"},
	}

	// 先获取所有基础镜像
	baseImages, _, err := s.imageDal.SearchImage(ctx, daoParam)

	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Ints64("imageIds", param.ImageIds).Msg("ListBaseImageOfApp")
		return nil, 0, scani18.GetImageInfo(err)
	}

	baseImageIds := make([]int64, 0)
	for i := range baseImages {
		if baseImages[i].LayerStr != "" && strings.HasPrefix(appImage.LayerStr, baseImages[i].LayerStr) {
			baseImageIds = append(baseImageIds, baseImages[i].ID)
		}
	}

	if len(baseImageIds) == 0 {
		return empty, 0, nil
	}
	assParam := imagesecModel.ImageAssociateParam{
		RegistryEnable:   true,
		SubtaskEnable:    true,
		VulnEnable:       true,
		NodeInfoEnable:   true,
		RiskPolicyEnable: true,
	}

	baseInfo, cnt, err := s.ListImageWithScanInfo(ctx, imagesecModel.ImageSearchApiParam{ImageIds: baseImageIds, AssociateParam: assParam})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Ints64("imageIds", param.ImageIds).Msg("ListBaseImageOfApp")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("ListBaseImageOfApp"))
	}
	return baseInfo, cnt, nil

}

// 获取基础镜像的应用的镜像列表
func (s *ImageInfoMetaSrv) ListAppImageOfBase(ctx context.Context, param imagesecModel.ImageSearchApiParam) (
	[]*imagesecModel.ImageBaseResponse, int64, error) {

	empty := make([]*imagesecModel.ImageBaseResponse, 0)
	if param.UniqueId <= 0 {
		return nil, 0, scani18.NotGetImageID()
	}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
		UniqueId: param.UniqueId,
		Fields:   []string{"id", "flag", "layer_str"}})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Ints64("imageIds", param.ImageIds).Msg("ListAppImageOfBase")
		return nil, 0, scani18.SearchImage(err)
	}
	// 对于from scratch的镜像，可能没有层级信息
	if len(images) == 0 || util.ExistBit1(images[0].Flag, imagesecModel.FlagAppImage) || images[0].LayerStr == "" {
		return empty, 0, nil
	}
	daoParam := imagesecModel.ImageDalParam{
		LayerStrPrefix: images[0].LayerStr,
		ImageFromType:  param.ImageFromType,
		Fields:         []string{"unique_id", "flag", "layer_str", "id"},
	}

	appImage, _, err := s.imageDal.SearchImage(ctx, daoParam)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Ints64("imageIds", param.ImageIds).Msg("ListAppImageOfBase")
		return nil, 0, scani18.SearchImage(err)
	}
	appImageIds := make([]int64, 0)
	for i := range appImage {
		if util.ExistBit1(appImage[i].Flag, imagesecModel.FlagAppImage) {
			appImageIds = append(appImageIds, appImage[i].ID)
		}
	}
	if len(appImageIds) == 0 {
		return empty, 0, nil
	}

	assParam := imagesecModel.ImageAssociateParam{
		RegistryEnable:   true,
		SubtaskEnable:    true,
		VulnEnable:       true,
		NodeInfoEnable:   true,
		RiskPolicyEnable: true,
	}

	appInfo, cnt, err := s.ListImageWithScanInfo(ctx, imagesecModel.ImageSearchApiParam{ImageIds: appImageIds, AssociateParam: assParam})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Ints64("imageIds", param.ImageIds).Msg("ListBaseImageOfApp")
		return nil, 0, scani18.SearchImage(err)
	}
	return appInfo, cnt, nil
}

func (s *ImageUpdateSrv) groupRegProject(ctx context.Context, param imagesecModel.SearchProjectParam) (
	[]imagesecModel.GroupProject, error) {
	param.ImageFromType = imagesecModel.ImageFromRegistry
	repos, err := s.imageDal.SearchProject(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("GetRegistryProject.GroupRegistryProject")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	resMap := make(map[int64][]imagesecModel.Project)
	for i := range repos {
		repos[i].Label = repos[i].Project
	}
	// 查出所有的registry
	registries, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("GetRegistryProject.SearchRegistry")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	regMap := make(map[int64]imagesecModel.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}

	for i := range repos {
		if _, ok := regMap[repos[i].RegID]; !ok {
			continue
		}
		repo := repos[i]
		repo.Value = fmt.Sprintf("%d,%s", repo.RegID, repo.Project)

		if resMap[repo.RegID] == nil {
			resMap[repo.RegID] = make([]imagesecModel.Project, 0)
		}
		resMap[repo.RegID] = append(resMap[repo.RegID], repo)
	}
	res := make([]imagesecModel.GroupProject, 0)
	for k, v := range resMap {
		res = append(res, imagesecModel.GroupProject{
			Children: v,
			Label:    fmt.Sprintf("%s(%s)", regMap[k].Name, regMap[k].Url),
			Value:    fmt.Sprintf("%d", k),
		})
	}
	return res, nil
}

func (s *ImageUpdateSrv) groupNodeProject(ctx context.Context, param imagesecModel.SearchProjectParam) (
	[]imagesecModel.GroupProject, error) {
	param.ImageFromType = imagesecModel.ImageFromNode
	repos, err := s.imageDal.SearchProject(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("GetRegistryProject.GroupRegistryProject")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	resMap := make(map[uint64][]imagesecModel.Project)
	for i := range repos {
		repos[i].Label = repos[i].Project
	}
	nodes, _, err := s.nodeDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("GetRegistryProject.SearchRegistry")
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
		repo.Value = fmt.Sprintf("%d,%s", repo.NodeUniqueID, repo.Project)

		if resMap[repo.NodeUniqueID] == nil {
			resMap[repo.NodeUniqueID] = make([]imagesecModel.Project, 0)
		}
		resMap[repo.NodeUniqueID] = append(resMap[repo.NodeUniqueID], repo)
	}
	res := make([]imagesecModel.GroupProject, 0)
	for k, v := range resMap {
		res = append(res, imagesecModel.GroupProject{
			Children: v,
			Label:    nodeMap[k].Hostname,
			Value:    fmt.Sprintf("%d", k),
		})
	}
	return res, nil
}

// 周期执行
func (s *ImageUpdateSrv) UpdateProject(ctx context.Context) error {

	lib, err := s.groupRegProject(ctx, imagesecModel.SearchProjectParam{ImageFromType: imagesecModel.ImageFromRegistry})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupRegProject")
		return err
	}
	metaGlobal.GetPrepareData().SetRegGroupProject(lib)

	node, err := s.groupNodeProject(ctx, imagesecModel.SearchProjectParam{ImageFromType: imagesecModel.ImageFromNode})
	if err != nil {

		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupNodeProject")
		return err

	}
	metaGlobal.GetPrepareData().SetNodeGroupProject(node)

	return nil
}

// 周期执行
func (s *ImageUpdateSrv) UpdateImagePrepareData(ctx context.Context) error {
	res := &imagesecModel.ImagePrepareData{}
	lib, err := s.groupRegProject(ctx, imagesecModel.SearchProjectParam{ImageFromType: imagesecModel.ImageFromRegistry})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupRegProject")
		return err
	}
	res.RegGroupProject = lib

	node, err := s.groupNodeProject(ctx, imagesecModel.SearchProjectParam{ImageFromType: imagesecModel.ImageFromNode})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupNodeProject")
		return err
	}

	res.NodeGroupProject = node

	libO, err := s.GetImageOverViewHelper(ctx, imagesecModel.ImageFromRegistry)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupRegProject")
		return err
	}
	res.RegImageOverView = libO

	nodeO, err := s.GetImageOverViewHelper(ctx, imagesecModel.ImageFromNode)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupNodeProject")
		return err
	}
	res.NodeImageOverView = nodeO

	cache := &imagesecModel.CacheInfo{
		DataType:         imagesecModel.CacheTypeImagePrepare,
		ImagePrepareData: res,
	}
	if err := s.imageCacheDal.CreateCacheInfo(ctx, cache); err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("CreateCacheInfo")
		return err
	}

	return err
}

// 周期执行
func (s *ImageUpdateSrv) UpdateImageOverView(ctx context.Context) error {

	lib, err := s.GetImageOverViewHelper(ctx, imagesecModel.ImageFromRegistry)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupRegProject")
		return err
	}
	metaGlobal.GetPrepareData().SetRegImageOverView(lib)

	node, err := s.GetImageOverViewHelper(ctx, imagesecModel.ImageFromNode)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("groupNodeProject")
		return err
	}
	metaGlobal.GetPrepareData().SetNodeImageOverView(node)

	return nil
}

func (s *ImageUpdateSrv) GetImageOverViewHelper(ctx context.Context, imageFromType string) (imagesecModel.SecurityStatistic, error) {

	overView := imagesecModel.SecurityStatistic{}
	// 查总数
	groups, err := s.imageDal.GroupImageFlags(ctx, imagesecModel.ImageGroupParam{ImageFromType: imageFromType})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("GetImageOverViewHelper.GroupImageFlags")
		return overView, scani18.SearchImage(err)
	}

	return imagesecStore.ToSecurityOverView(groups), nil
}

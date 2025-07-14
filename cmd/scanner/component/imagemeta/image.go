package imagemeta

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta/metaGlobal"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageService interface {
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageSearchApiParam) ([]*imagesecModel.ImageBaseResponse, int64, error)
	SearchProject(ctx context.Context, param imagesecModel.SearchProjectParam) ([]imagesecModel.GroupProject, error)
	UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error
	// 查询很重的接口，慎重传参
	GetImageCorrelateData(ctx context.Context, param imagesecModel.ImageAssociateParam) (*imagesecModel.ImageWithCorrelateData2, error)
	GetImageOverView(ctx context.Context) (*imagesecModel.ImagePrepareData, error)
	TopRiskImage(ctx context.Context) ([]*imagesecModel.ImageBaseResponse, error)
	SearchResources(ctx context.Context, param imagesecModel.SearchResourceParam) ([]model.TensorRawContainer, int64, error)
	GetImageForDeploy(ctx context.Context, param imagesecModel.DeployMonitorImage) GetImageForDeployRes
	SearchRelatedImage(ctx context.Context, param imagesecModel.RelatedSearchParam) ([]imagesecModel.RelatedImageRes, int64, error)
}

type ImageInfoMetaSrv struct {
	imageDal        imagesecStore.ImageMetaDal
	registryDal     imagesecStore.RegistryDal
	scanResultDal   imagesecStore.ScanResultDal
	resourceDal     imagesecStore.ResourceDal
	nodeDal         imagesecStore.NodeInfoDal
	scanInstanceDal imagesecStore.ScanInstanceDal
	policyDal       imagesecStore.DetectPolicyDal
	detectResultDal imagesecStore.ImageDetectResultDal
	trustedDal      adaptStore.TrustedImageDal
	configDal       imagesecStore.ScanImageConfigDal
	scanTaskDal     imagesecStore.ScanTaskDal
	deployRecordDal imagesecStore.DeployDal
	imageCacheDal   imagesecStore.ImageCacheDal

	RiskImageTop5 *metaGlobal.RiskImageTop5

	Log *scannerUtils.LogEvent
}

func NewImageMetaSrv(
	imageDal imagesecStore.ImageMetaDal,
	registryDal imagesecStore.RegistryDal,
	scanResultDal imagesecStore.ScanResultDal,
	resourceDal imagesecStore.ResourceDal,
	nodeInfoDal imagesecStore.NodeInfoDal,
	policyDal imagesecStore.DetectPolicyDal,
	detectResultDal imagesecStore.ImageDetectResultDal,
	trustedDal adaptStore.TrustedImageDal,
	configDal imagesecStore.ScanImageConfigDal,
	scanTaskDal imagesecStore.ScanTaskDal,
	scanInstanceDal imagesecStore.ScanInstanceDal,
	deployRecordDal imagesecStore.DeployDal,
	imageCacheDal imagesecStore.ImageCacheDal,
) *ImageInfoMetaSrv {
	srv := ImageInfoMetaSrv{
		imageDal:        imageDal,
		registryDal:     registryDal,
		scanResultDal:   scanResultDal,
		resourceDal:     resourceDal,
		nodeDal:         nodeInfoDal,
		scanInstanceDal: scanInstanceDal,
		policyDal:       policyDal,
		detectResultDal: detectResultDal,
		trustedDal:      trustedDal,
		configDal:       configDal,
		scanTaskDal:     scanTaskDal,
		deployRecordDal: deployRecordDal,
		imageCacheDal:   imageCacheDal,
		RiskImageTop5:   metaGlobal.GetRiskImageTop5(),

		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("MetaInfo"),
			scannerUtils.WithModule(consts.ModuleImageMeta),
		),
	}
	return &srv
}

func (s *ImageInfoMetaSrv) ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageSearchApiParam) (
	[]*imagesecModel.ImageBaseResponse, int64, error) {

	res := make([]*imagesecModel.ImageBaseResponse, 0)

	s.Log.Trace().Interface("param", param).Msg("ListImageWithScanInfo")

	daoParam := param.ToImageDalParam()

	daoParam.Fields = []string{"id", "unique_id"}

	s.Log.Trace().Interface("daoParam", daoParam).Interface("filter", param.Filter).Msg("SearchImageWithScan SearchImage")

	images, cnt, err := s.imageDal.SearchImage(ctx, daoParam)
	if err != nil {
		s.Log.Err(err).Msg("SearchImageWithScan.SearchImage")
		return nil, 0, err
	}

	if len(images) == 0 {
		return res, 0, nil
	}

	// 转换数据
	for i := range images {
		param.AssociateParam.ImageId = images[i].ID
		param.AssociateParam.ImageUniqueID = images[i].UniqueID
		param.AssociateParam.SearchVulnParam.Fields = []string{"severity"}
		param.AssociateParam.ContainerEnable = true
		// 其他数据
		data, err := s.GetImageCorrelateData(ctx, param.AssociateParam)
		if err != nil {
			s.Log.Err(err).Msg("SearchImageWithScan.GetImageCorrelateData")
			return nil, 0, err
		}
		baseImageInfo := data.ToImageBaseResponse()
		res = append(res, &baseImageInfo)
	}

	return res, cnt, nil
}

func (s *ImageInfoMetaSrv) UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error {
	err := s.imageDal.UpdateImage(ctx, param)
	if err != nil {
		s.Log.Err(err).Interface("param", param).Msg("UpdateImage")
		return err
	}
	return nil
}

func (s *ImageInfoMetaSrv) GetImageCorrelateData(ctx context.Context,
	param imagesecModel.ImageAssociateParam) (*imagesecModel.ImageWithCorrelateData2, error) {

	param.Deserialize()

	filter := param.ScanResultSearchParam.Filter.DeepCopy()

	if param.ScanResultSearchParam.Filter != nil {
		param.ScanResultSearchParam.Filter = param.ScanResultSearchParam.Filter.SetLimit(0).SetOffset(0)
	}

	// 程序中分页
	if param.SearchVulnParam.Filter != nil {
		param.SearchVulnParam.Filter = param.SearchVulnParam.Filter.SetLimit(0).SetOffset(0)
	}

	if err := param.Check(); err != nil {
		return nil, err
	}

	ans := &imagesecModel.ImageWithCorrelateData2{
		Image:             imagesecModel.Image{},
		ImageBaseResponse: imagesecModel.ImageBaseResponse{},
		Sensitive:         make([]*imagesecModel.SensitiveFile, 0),
		WebshellView:      make([]*imagesecModel.WebshellView, 0),
		Env:               make([]*imagesecModel.ImageEnv, 0),
		Vuln:              make([]*imagesecModel.VulnView, 0),
		Pkg:               make([]*imagesecModel.Pkg, 0),
		License:           make([]*imagesecModel.License, 0),
		Malware:           make([]*imagesecModel.Malware, 0),
		BaseImages:        make([]*imagesecModel.ImageBaseResponse, 0),
		AppImages:         make([]*imagesecModel.ImageBaseResponse, 0),
		Container:         make([]*imagesecModel.RawContainer, 0),
		ScanSubTask:       make([]*imagesecModel.ImageScanSubTask, 0),
		TrustedImage:      make([]imagesecModel.TrustedImage, 0),
		ImageInReg:        make([]imagesecModel.ImageInReg, 0),
		RootBoot:          make([]imagesecModel.RootBoot, 0),
		RiskPolicy:        make([]imagesecModel.SecurityPolicy, 0),
		TotalPolicy:       make([]imagesecModel.SecurityPolicy, 0),
		DetectResult:      make(map[string][]*imagesecModel.ImageDetectResult),
	}

	if err := s.addImageMeta(ctx, &param, ans); err != nil {
		s.Log.Err(err).Int64("ImageID", param.ImageId).
			Msg("ImageWithCorrelateData addImageMeta")
		return nil, err
	}

	if err := s.addDeployMeta(ctx, &param, ans); err != nil {
		s.Log.Err(err).Int64("ImageID", param.ImageId).Msg("ImageWithCorrelateData addDeployMeta")
		return nil, err
	}

	// 对于老版本的集群，是扫描器扫描后，直接写数据库保存漏洞等数据，然后把其他结果发送kafka
	// 如果在写入数据库后，发送 kafka失败，就不会执行后续检测逻辑，此时就会出现一种情况是：有扫描数据，但是安全状态还是未知
	// 鉴于我们的 kafka 及数据库经常重启,需要做一下兼容。
	// 镜像表中的flag 字段保存很多信息，但是 flag 的更新逻辑是，读取数据->计算值->再更新回数据库，这种方式难免会有数据更新冲突，
	// 解决办法是用事务，因为更新 flag 是一个很频繁的操作，如果用事务会严重影响性能
	// 这里统一做一下兼容
	if param.ImageFromType != imagesecModel.ImageFromDeploy && !param.NotNeedCompImageSafe && ans.GenSafe() == imagesecModel.ImageSafeUnknown {
		param.VulnEnable = false
		param.SensitiveEnable = false
		param.MalwareEnable = false
		param.WebshellEnable = false
		param.LicenseEnable = false
		param.SubtaskEnable = false
		param.PkgEnable = false
		param.RiskPolicyEnable = false
		param.SimplePolicyEnable = false
	}

	s.Log.Trace().Interface("param", param).Any("ans", ans).Msg("GetImageCorrelateData")

	errs := make([]error, 0)
	errs = append(errs, s.addRegistryData(ctx, &param, ans))
	errs = append(errs, s.addScannerInfoData(ctx, &param, ans))
	errs = append(errs, s.addEnvData(ctx, &param, ans))
	errs = append(errs, s.addSensitiveData(ctx, &param, ans))
	errs = append(errs, s.addPkgData(ctx, &param, ans))
	errs = append(errs, s.addLicenseData(ctx, &param, ans))
	errs = append(errs, s.addMalwareData(ctx, &param, ans))
	errs = append(errs, s.addWebshellData(ctx, &param, ans))
	errs = append(errs, s.addVulnData(ctx, &param, ans))
	errs = append(errs, s.addFinishedSubtaskData(ctx, &param, ans))
	errs = append(errs, s.addContainerData(ctx, &param, ans))
	errs = append(errs, s.addBaseAppData(ctx, &param, ans))
	errs = append(errs, s.addTrustedData(ctx, &param, ans))
	errs = append(errs, s.addImageInRegData(ctx, &param, ans))
	errs = append(errs, s.addNodeInfoData(ctx, &param, ans))
	errs = append(errs, s.addImageRiskPolicyData(ctx, &param, ans))
	errs = append(errs, s.addSimplePolicyData(ctx, &param, ans))
	errs = append(errs, s.addDetectResultData(ctx, &param, ans))
	errs = append(errs, s.addPkgAllVulnData(ctx, &param, ans))
	errs = append(errs, s.addRootBootData(ctx, &param, ans))

	notNilErr := make([]string, 0)
	for i := range errs {
		if errs[i] != nil {
			s.Log.Err(errs[i]).Int64("imageID", ans.Image.ID).Msg("GetImageCorrelateData")
			notNilErr = append(notNilErr, errs[i].Error())
		}
	}
	if len(notNilErr) > 0 {
		return ans, fmt.Errorf(strings.Join(notNilErr, ","))
	}

	ans.AddDetectResult()

	ans.AddDeployDetect()

	ans.ExceptionFilter(param.ScanResultSearchParam)

	// 只判断返回的数据
	_ = s.addCheckDownloadable(ctx, &param, ans)

	ans.ImageBaseResponse = ans.ToImageBaseResponse()
	base := ans.ImageBaseResponse

	// 用于top5的镜像统计
	go func() {
		if !param.RegistryEnable || !param.NodeInfoEnable ||
			!param.VulnEnable || !param.SensitiveEnable || !param.WebshellEnable ||
			!param.MalwareEnable {
			return
		}

		metaGlobal.GetRiskImageTop5().Add(&base)
	}()
	// 程序中分页
	ans = ans.AddFilter(filter)
	s.Log.Trace().Any("ans", ans).Msg("GetImageCorrelateData")
	return ans, nil
}

// 搜索是前端做的，后端返回全量数据
func (s *ImageInfoMetaSrv) SearchProject(ctx context.Context, param imagesecModel.SearchProjectParam) (
	[]imagesecModel.GroupProject, error) {
	if err := param.Check(); err != nil {
		return nil, scani18.GetImageFromType()
	}
	info, err := s.imageCacheDal.SearchCacheInfo(ctx, imagesecModel.CacheTypeImagePrepare)
	if err != nil {
		s.Log.Err(err).Msg("SearchProject")
		return nil, err
	}

	if info.ImagePrepareData == nil {
		return nil, scani18.SearchImage(err)
	}

	switch param.ImageFromType {
	case imagesecModel.ImageFromNode:
		return info.ImagePrepareData.NodeGroupProject, nil
	case imagesecModel.ImageFromRegistry:
		return info.ImagePrepareData.RegGroupProject, nil
	default:
		return make([]imagesecModel.GroupProject, 0), scani18.GetImageFromType()
	}
}

func (s *ImageInfoMetaSrv) GetImageOverView(ctx context.Context) (*imagesecModel.ImagePrepareData, error) {
	ans := &imagesecModel.ImagePrepareData{}
	info, err := s.imageCacheDal.SearchCacheInfo(ctx, imagesecModel.CacheTypeImagePrepare)
	if err != nil {
		s.Log.Err(err).Msg("SearchProject")
		return ans, err
	}

	if info.ImagePrepareData == nil {
		return ans, scani18.SearchImage(err)
	}
	return info.ImagePrepareData, nil
}

func (s *ImageInfoMetaSrv) TopRiskImage(ctx context.Context) ([]*imagesecModel.ImageBaseResponse, error) {
	if s.RiskImageTop5.Exit() {

		ans := s.RiskImageTop5.Get()
		if len(ans) >= 5 {
			return ans, nil
		}
	}
	images, _, err := s.ListImageWithScanInfo(ctx, imagesecModel.ImageSearchApiParam{
		OnlineStr:  []string{consts.TrueString},
		SafeAttr:   []string{imagesecModel.ImageUnsafeString},
		VulnStatic: []string{imagesecModel.SeverityCritical, imagesecModel.SeverityHigh},
		AssociateParam: imagesecModel.ImageAssociateParam{
			VulnEnable:         true,
			MalwareEnable:      true,
			SensitiveEnable:    true,
			WebshellEnable:     true,
			SubtaskEnable:      true,
			RegistryEnable:     true,
			ScanInstanceEnable: true,
			NodeInfoEnable:     true,
		},
		Filter: imagesecModel.EmptyFilter().SetLimit(consts.DefaultPerPage),
	})
	if err != nil {
		s.Log.Err(err).Msg("TopRiskImage")
		return nil, err
	}
	s.RiskImageTop5.Add(images...)
	o := s.RiskImageTop5.Get()
	return o, nil
}

func (s *ImageInfoMetaSrv) SearchResources(ctx context.Context, param imagesecModel.SearchResourceParam) (
	[]model.TensorRawContainer, int64, error) {
	resources, cnt, err := s.resourceDal.SearchResources(ctx, param)
	if err != nil {
		s.Log.Err(err).Interface("param", param).Msg("SearchResources")
		return nil, 0, scani18.SearchResource(err)
	}
	ans := make([]model.TensorRawContainer, 0)
	for i := range resources {
		ans = append(ans, resources[i].TensorRawContainer)
	}

	return ans, cnt, nil
}

func (s *ImageInfoMetaSrv) SearchRelatedImage(ctx context.Context, param imagesecModel.RelatedSearchParam) (
	[]imagesecModel.RelatedImageRes, int64, error) {

	ans := make([]imagesecModel.RelatedImageRes, 0)
	if err := param.Check(); err != nil {
		return ans, 0, err
	}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
		VulnUniqueID: param.VulnUniqueID,
		PkgUniqueID:  param.PkgUniqueID,
		WebshellMD5:  param.WebshellMD5,
		MalwareMD5:   param.MalwareMd5,
		SensitiveMD5: param.SensitiveMd5,
	})
	filter := param.Filter.DeepCopy()
	if param.ImageKeyword != "" {
		param.Filter = nil
	}

	if err != nil {
		s.Log.Err(err).Msg("SearchRelatedImage SearchImage")
		return ans, 0, scani18.SearchImage(err)
	}
	if len(images) == 0 {
		return ans, 0, nil
	}
	uuids := make([]uint32, 0)
	for i := range images {
		uuids = append(uuids, images[i].ImageUUID)
	}

	uuids = util.DuplicateUint32Slice(uuids)

	res := make(map[uint32]imagesecModel.RelatedImageRes)

	regIds := make([]int64, 0)
	nodeIds := make([]uint64, 0)
	regMap := make(map[int64]*imagesecModel.Registry)
	nodeMap := make(map[uint64]*imagesecModel.NodeInfo)
	resourceMap := make(map[uint32]model.TensorRawContainer)
	for i := range images {
		if images[i].NodeID > 0 {
			nodeIds = append(nodeIds, images[i].NodeID)
		}
		if images[i].RegID > 0 {
			regIds = append(regIds, images[i].RegID)
		}
	}
	regIds = util.DuplicateInt64Slice(regIds)
	nodeIds = util.DuplicateUint64Slice(nodeIds)

	regs, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{RegIds: regIds})
	if err != nil {
		s.Log.Err(err).Msg("SearchRelatedImage SearchRegistry")
		return nil, 0, scani18.SearchImage(err)
	}
	for i := range regs {
		regMap[regs[i].ID] = &(regs[i])
	}
	nodes, _, err := s.nodeDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{UniqueIds: nodeIds})
	if err != nil {
		s.Log.Err(err).Msg("SearchRelatedImage SearchNodeInfo")
		return nil, 0, scani18.SearchImage(err)
	}
	for i := range nodes {
		nodeMap[nodes[i].UniqueID] = nodes[i]
	}
	resources, _, err := s.resourceDal.SearchResources(ctx, imagesecModel.SearchResourceParam{ImageUUIDs: uuids, Fields: []string{"image_uuid", "name"}})
	if err != nil {
		s.Log.Err(err).Msg("SearchRelatedImage SearchResources")
		return nil, 0, scani18.SearchImage(err)
	}

	for i := range resources {
		resourceMap[resources[i].TensorRawContainer.ImageUUID] = resources[i].TensorRawContainer
	}

	for i := range images {
		ima := images[i]
		uuid := ima.ImageUUID
		if _, ok := res[images[i].ImageUUID]; !ok {
			im := imagesecModel.RelatedImageRes{
				ImageID:       ima.ID,
				ImageUUID:     ima.ImageUUID,
				Digest:        ima.Digest,
				ImageFromType: ima.ImageFromType,
				ImageUniqueID: ima.UniqueID,
				Image:         ima.GetImageName(),
				Registry:      make([]imagesecModel.RegistrySimple, 0),
				Node:          make([]*imagesecModel.NodeInfo, 0),
				Container:     make([]string, 0),
			}
			res[uuid] = im
		}
		im := res[uuid]

		if reg, ok := regMap[images[i].RegID]; ok {
			reg1 := reg.Simplify()
			im.Registry = append(im.Registry, reg1)
		}
		if no, ok := nodeMap[images[i].NodeID]; ok {
			im.Node = append(im.Node, no)
		}
		if cn, ok := resourceMap[images[i].ImageUUID]; ok {
			im.Container = append(im.Container, cn.Name)
		}

		res[uuid] = im
	}

	for i := range res {
		an := res[i]
		an.Container = util.DuplicateStringSlice(an.Container)
		if param.ImageKeyword != "" && !an.HasKeyword(param.ImageKeyword) {
			continue
		}
		ans = append(ans, an)
	}

	cnt := int64(len(ans))

	start := int(filter.Offset)
	end := int(filter.Offset + filter.Limit)

	if len(ans) <= start {
		return ans, cnt, nil
	}
	if end > len(ans) {
		end = len(ans)
	}
	ans = ans[start:end]
	if len(ans) == 0 {
		return ans, cnt, nil
	}
	ansUuids := make([]uint32, 0)
	for i := range ans {
		ansUuids = append(ansUuids, ans[i].ImageUUID)
	}
	ass := imagesecModel.ImageAssociateParam{RegistryEnable: true, NodeInfoEnable: true}
	infos, _, err := s.ListImageWithScanInfo(ctx, imagesecModel.ImageSearchApiParam{UUIDs: ansUuids, AssociateParam: ass})
	if err != nil {
		return ans, cnt, scani18.SearchImage(err)
	}

	uuidReg := make(map[uint32][]imagesecModel.RegistrySimple)
	uuidNode := make(map[uint32][]*imagesecModel.NodeInfo)

	for i := range infos {
		in := infos[i]
		if uuidReg[in.UUID] == nil {
			uuidReg[in.UUID] = make([]imagesecModel.RegistrySimple, 0)
		}
		if in.ImageFromType == imagesecModel.ImageFromRegistry {
			uuidReg[in.UUID] = append(uuidReg[in.UUID], imagesecModel.RegistrySimple{
				ID:   in.RegistryID,
				Name: in.RegistryName,
				Url:  in.RegistryUrl,
			})
		}
	}

	for i := range infos {
		in := infos[i]
		if uuidNode[in.UUID] == nil {
			uuidNode[in.UUID] = make([]*imagesecModel.NodeInfo, 0)
		}
		if in.ImageFromType == imagesecModel.ImageFromNode {
			uuidNode[in.UUID] = append(uuidNode[in.UUID], &imagesecModel.NodeInfo{
				UniqueID:    in.NodeUniqueID,
				Hostname:    in.NodeHostname,
				ClusterKey:  in.ClusterKey,
				ClusterName: in.ClusterName,
			})
		}
	}
	for i := range ans {
		ans[i].Registry = uuidReg[ans[i].ImageUUID]
		ans[i].Node = uuidNode[ans[i].ImageUUID]
		if len(ans[i].Registry) == 0 {
			ans[i].Registry = make([]imagesecModel.RegistrySimple, 0)
		}
		if len(ans[i].Node) == 0 {
			ans[i].Node = make([]*imagesecModel.NodeInfo, 0)
		}
	}

	return ans, cnt, nil
}

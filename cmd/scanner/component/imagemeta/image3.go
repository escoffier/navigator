package imagemeta

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *ImageInfoMetaSrv) addImageMeta(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {

	// 节点镜像和仓库镜像
	if param.ImageId <= 0 && param.ImageUniqueID <= 0 {
		return nil
	}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
		ID: param.ImageId, UniqueId: param.ImageUniqueID})
	if err != nil {
		s.Log.Err(err).Int64("ImageID", param.ImageId).Msg("ImageWithCorrelateData ImageBaseDetail")
		return err
	}
	if len(images) == 0 {
		return scani18.NotGetImage()
	}
	image := images[0]
	ans.Image = *image

	param.ScanResultSearchParam.ImageUniqueID = ans.Image.UniqueID
	param.ScanResultSearchParam.ImageID = ans.Image.ID
	param.SearchVulnParam.ImageID = ans.Image.ID
	param.SearchVulnParam.ImageUniqueID = ans.Image.UniqueID

	param.ImageUniqueID = image.UniqueID

	return nil
}

func (s *ImageInfoMetaSrv) addDeployMeta(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {

	if param.DeployRecordID <= 0 {
		return nil
	}

	if err := s.addDeployImageMeta(ctx, param, ans); err != nil {
		return err
	}
	return nil
}

func (s *ImageInfoMetaSrv) addDeployImageMeta(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	if param.DeployRecordID <= 0 {
		return scani18.NotGetID()
	}

	record, _, err := s.deployRecordDal.SearchDeployRecord(ctx, imagesecModel.ImageDalParam{ID: param.DeployRecordID})
	if err != nil {
		return scani18.SearchDeployRecord(err)
	}
	if len(record) == 0 {
		return scani18.SearchDeployRecord(fmt.Errorf("not find record"))
	}
	rec := record[0]

	if rec.Action == imagesecModel.DeployActionPass {
		ans.DeployInWhite = true
	}

	// 详情页面也要判断是否在白名单中
	if rec.Action != imagesecModel.DeployActionPass {
		white, _, err := s.deployRecordDal.SearchDeployWhiteImage(ctx, imagesecModel.SearchDeployWhiteImageParam{})
		if err != nil {
			return scani18.SearchDeployRecord(err)
		}
		wp := make(map[string]*regexp.Regexp)
		for i := range white {
			if white[i].ExpirationAt <= time.Now().UnixMilli() {
				continue
			}
			if compile, err := regexp.Compile(white[i].ImageName); err == nil {
				wp[white[i].ImageName] = compile
			}
		}

		for _, re := range wp {
			if re.FindString(rec.ImageName) != "" {
				ans.DeployInWhite = true
				break
			}
		}
	}

	rec.Image.CreatedAt = rec.CreatedAt
	ans.Image = rec.Image
	ans.DeployRecord = rec
	ans.Image.Flag = rec.Flag

	return nil
}

func (s *ImageInfoMetaSrv) addEnvData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {

	if ans.DeployRecord != nil {
		param.ScanResultSearchParam.UniqueIds = ans.DeployRecord.Env
	}

	if param.EnvEnable && (param.ScanResultSearchParam.ImageUniqueID > 0 || len(param.ScanResultSearchParam.UniqueIds) > 0) {
		env, cnt, err := s.scanResultDal.SearchImageEnv(ctx, param.ScanResultSearchParam)
		if err != nil {
			s.Log.Err(err).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData SearchImageEnv")
			return err
		}
		ans.Env = env
		ans.EnvCnt = cnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addSensitiveData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {

	if ans.DeployRecord != nil {
		param.ScanResultSearchParam.UniqueIds = ans.DeployRecord.Sensitive
	}

	if param.SensitiveEnable && (param.ScanResultSearchParam.ImageUniqueID > 0 || len(param.ScanResultSearchParam.UniqueIds) > 0) {
		sensitive, cnt, err := s.scanResultDal.SearchSensitive(ctx, param.ScanResultSearchParam)
		if err != nil {
			s.Log.Err(err).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData SearchSensitive")
			return err
		}
		ans.Sensitive = sensitive
		ans.SensitiveCnt = cnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addPkgData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID

	if ans.DeployRecord != nil {
		param.ScanResultSearchParam.UniqueIds = ans.DeployRecord.Pkg
	}

	if param.PkgEnable && (param.ScanResultSearchParam.ImageUniqueID > 0 || len(param.ScanResultSearchParam.UniqueIds) > 0) {
		pkg, cnt, err := s.scanResultDal.SearchPkg(ctx, param.ScanResultSearchParam)
		if err != nil {
			s.Log.Err(err).Int64("ImageID", imageID).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData SearchPkg")
			return err
		}
		ans.Pkg = pkg
		ans.PkgCnt = cnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addLicenseData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID

	if ans.DeployRecord != nil {
		param.ScanResultSearchParam.UniqueIds = ans.DeployRecord.License
	}

	if param.LicenseEnable && (param.ScanResultSearchParam.ImageUniqueID > 0 || len(param.ScanResultSearchParam.UniqueIds) > 0) {
		license, cnt, err := s.scanResultDal.SearchLicense(ctx, param.ScanResultSearchParam)
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData SearchLicense")
			return err
		}
		ans.License = license
		ans.LicenseCnt = cnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addMalwareData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID

	if ans.DeployRecord != nil {
		param.ScanResultSearchParam.UniqueIds = ans.DeployRecord.Malware
	}

	if param.MalwareEnable && (param.ScanResultSearchParam.ImageUniqueID > 0 || len(param.ScanResultSearchParam.UniqueIds) > 0) {
		virus, cnt, err := s.scanResultDal.SearchMalware(ctx, param.ScanResultSearchParam)
		if err != nil {
			s.Log.Err(err).Int64("ImageID", imageID).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData SearchVirus")
			return err
		}
		ans.Malware = virus
		ans.MalwareCnt = cnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addWebshellData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {

	imageID := ans.Image.ID

	if ans.DeployRecord != nil {
		param.ScanResultSearchParam.UniqueIds = ans.DeployRecord.Webshell
	}

	if param.WebshellEnable && (param.ScanResultSearchParam.ImageUniqueID > 0 || len(param.ScanResultSearchParam.UniqueIds) > 0) {
		webshell, webshellCnt, err := s.scanResultDal.SearchWebshell(ctx, param.ScanResultSearchParam)
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("SearchImageWithScan.SearchWebshell")
			return err
		}
		ans.WebshellCnt = webshellCnt

		ans.WebshellView = make([]*imagesecModel.WebshellView, len(webshell))
		for i := range webshell {
			ans.WebshellView[i] = webshell[i].ToWebshellView()
		}
	}
	return nil
}

func (s *ImageInfoMetaSrv) addVulnData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID

	if ans.DeployRecord != nil {
		param.SearchVulnParam.VulnUniqueIds = ans.DeployRecord.Vuln
	}

	if param.VulnEnable && (param.SearchVulnParam.ImageUniqueID > 0 || len(param.SearchVulnParam.VulnUniqueIds) > 0) {

		vuln, cnt, err := s.scanResultDal.SearchVuln(ctx, param.SearchVulnParam.ToDaoSearchVulnParam())
		if err != nil {
			s.Log.Err(err).Int64("ImageID", imageID).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData SearchVuln")
			return err
		}
		vulns := make([]*imagesecModel.VulnView, len(vuln))
		for i := range vuln {
			vulns[i] = vuln[i].GenVulnView()
		}

		ans.Vuln = vulns
		ans.VulnCnt = cnt
	}
	return nil
}

// 一定要先查软件包
func (s *ImageInfoMetaSrv) addPkgAllVulnData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID

	if ans.DeployRecord != nil {
		param.SearchVulnParam.VulnUniqueIds = ans.DeployRecord.Vuln
	}
	pkgUniqueIds := make([]uint64, 0)
	for i := range ans.Pkg {
		pkgUniqueIds = append(pkgUniqueIds, ans.Pkg[i].UniqueID)
	}

	if param.AllPkgVuln && len(pkgUniqueIds) > 0 {
		vuln, cnt, err := s.scanResultDal.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{
			PkgUniqueIds: pkgUniqueIds,
		})
		if err != nil {
			s.Log.Err(err).Int64("ImageID", imageID).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData addPkgAllVulnData")
			return err
		}
		vulns := make([]*imagesecModel.VulnView, len(vuln))
		for i := range vuln {
			vulns[i] = vuln[i].GenVulnView()
		}

		ans.Vuln = vulns
		ans.VulnCnt = cnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addFinishedSubtaskData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID
	// lastScanTask
	if param.SubtaskEnable && ans.Image.UniqueID > 0 {
		subtaskParam := imagesecModel.SearchTaskParam{
			ImageUniqueID: ans.Image.UniqueID,
			ScanStatus:    []int64{imagesecModel.TaskStatusDetectFinished, imagesecModel.TaskStatusScanFinished},
			Filter:        imagesecModel.EmptyFilter().SetSortDesc().SetSortFiledByID().SetLimit(1)}

		subtasks, cnt, err := s.scanTaskDal.SearchScanSubtask(ctx, subtaskParam)

		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchScanSubtask")
			return err
		}
		ans.ScanSubTask = subtasks
		ans.SubTaskCnt = cnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addContainerData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID
	// 导出时要用到
	if param.ContainerEnable && ans.Image.UniqueID > 0 {
		conParam := imagesecModel.SearchResourceParam{
			ImageUUID: ans.Image.ImageUUID,
		}

		raw, _, err := s.resourceDal.SearchResources(ctx, conParam)
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).Str("imageName", ans.Image.GetImageName()).
				Msg("ImageWithCorrelateData.SearchResources")
			return err
		}

		clusterKey := make([]string, 0)
		for i := range raw {
			clusterKey = append(clusterKey, raw[i].TensorRawContainer.ClusterKey)
		}
		if len(clusterKey) > 0 {
			clusterName, err := s.resourceDal.SearchClusterName(ctx, clusterKey)
			if err != nil {
				s.Log.Err(err).Int64("imageID", imageID).
					Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchClusterName")
			}
			for i := range raw {
				raw[i].ClusterName = clusterName[raw[i].TensorRawContainer.ClusterKey]
			}
		}
		ans.Container = raw
	}
	return nil
}

func (s *ImageInfoMetaSrv) addBaseAppData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID
	image := ans.Image
	// 获取应用镜像列表
	if param.AppImageEnable && util.ExistBit1(image.Flag, imagesecModel.FlagBaseImage) {
		appImageParam := imagesecModel.ImageSearchApiParam{
			UniqueId:      image.UniqueID,
			ImageKeyword:  param.ScanResultSearchParam.Keyword,
			ImageFromType: imagesecModel.ImageFromRegistry,
		}
		appImages, appImageCnt, err := s.ListAppImageOfBase(ctx, appImageParam)
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.ListAppImageOfBase")
			return err
		}
		ans.AppImages = appImages
		ans.AppImageCnt = appImageCnt
	}

	if param.BaseImageEnable && util.ExistBit1(image.Flag, imagesecModel.FlagAppImage) {
		baseImageParam := imagesecModel.ImageSearchApiParam{
			UniqueId:      image.UniqueID,
			ImageKeyword:  param.ScanResultSearchParam.Keyword,
			ImageFromType: imagesecModel.ImageFromRegistry,
		}

		baseImages, baseImageCnt, err := s.ListBaseImageOfApp(ctx, baseImageParam)
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchResources")
			return err
		}
		ans.BaseImages = baseImages
		ans.BaseImageCnt = baseImageCnt
	}
	return nil
}

func (s *ImageInfoMetaSrv) addTrustedData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	if !param.TrustedEnable {
		return nil
	}

	imageID := ans.Image.ID
	image := ans.Image
	trustedImage, err := s.trustedDal.SearchTrustedImage(ctx, adaptStore.SearchTrustedImageParam{Digests: []string{image.Digest}})
	if err != nil {
		s.Log.Err(err).Int64("imageID", imageID).
			Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData addTrustedData")
		return err
	}
	trustedDigest := make([]string, 0)
	for i := range trustedImage {
		if trustedImage[i].IsTrusted <= 0 {
			continue
		}
		trustedDigest = append(trustedDigest, trustedImage[i].Digest)
	}
	ans.TrustedImage = append(ans.TrustedImage, imagesecModel.TrustedImage{
		Trusted:      len(trustedDigest) > 0,
		Digest:       image.Digest,
		UniqueID:     image.UniqueID,
		PolicyDetect: imagesecModel.PolicyDetect{},
	})

	return nil
}

func (s *ImageInfoMetaSrv) addImageInRegData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	if !param.ImageInReg {
		return nil
	}

	imageID := ans.Image.ID
	image := ans.Image
	image.ImageUUID = image.GenUUID()

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UUIDs: []uint32{image.ImageUUID}})
	if err != nil {
		s.Log.Err(err).Int64("imageID", imageID).
			Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData addImageInRegData")
		return err
	}
	regIds := make([]int64, 0)

	for i := range images {
		im := images[i]
		if im.ImageUUID == ans.Image.ImageUUID && im.ImageFromType == imagesecModel.ImageFromRegistry && im.RegID > 0 {
			regIds = append(regIds, im.RegID)
		}
	}

	ans.ImageInReg = append(ans.ImageInReg, imagesecModel.ImageInReg{
		RegIds:       regIds,
		UniqueID:     ans.Image.UniqueID,
		PolicyDetect: imagesecModel.PolicyDetect{},
	})

	return nil
}

func (s *ImageInfoMetaSrv) addNodeInfoData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID
	image := ans.Image
	if param.NodeInfoEnable && image.NodeID > 0 {
		nodes, _, err := s.nodeDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{UniqueIds: []uint64{image.NodeID}})
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchNodeInfo")
			return err
		}
		if len(nodes) > 0 {
			cluster, err := s.resourceDal.SearchClusterName(ctx, []string{nodes[0].ClusterKey})
			if err != nil {
				s.Log.Err(err).Int64("imageID", imageID).
					Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchCluster")
			}
			nodes[0].ClusterName = cluster[nodes[0].ClusterKey]
			ans.NodeInfo = nodes[0]
		}
	}
	return nil
}

func (s *ImageInfoMetaSrv) addImageRiskPolicyData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageUniqueID := ans.Image.UniqueID

	// 以快照的方式，如果策略删除了，会重新检测，查询到中间状态是正常的
	if param.RiskPolicyEnable && param.DeployRecordID == 0 && imageUniqueID > 0 {

		brief, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
			ImageUniqueID: imageUniqueID, NeedPolicy: true})
		if err != nil {
			s.Log.Err(err).Str("imageName", ans.Image.GetImageName()).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchDetectBrief")
			return err
		}

		for i := range brief {
			if brief[i].Policy != nil {
				pn := brief[i].Policy
				ans.TotalPolicy = append(ans.TotalPolicy, *pn)
				if util.ExistBit1(brief[i].Flag, imagesecModel.FlagDetectException) {
					ans.RiskPolicy = append(ans.RiskPolicy, *pn)
				}
			}
		}
	}

	if param.RiskPolicyEnable && param.DeployRecordID > 0 && ans.DeployRecord != nil {
		uid := make([]uint64, 0)
		for _, rec := range ans.DeployRecord.RiskPolicy {
			uid = append(uid, rec.UniqueID)
		}
		snapshot, err := s.policyDal.SearchDetectPolicySnapshot(ctx, imagesecModel.SearchSecurityPolicyParam{UniqueIds: uid})
		if err != nil {
			s.Log.Err(err).Str("imageName", ans.Image.GetImageName()).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchDetectBrief")
			return err
		}

		ans.RiskPolicy = append(ans.RiskPolicy, snapshot...)
	}

	return nil
}

func (s *ImageInfoMetaSrv) addSimplePolicyData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID
	imageUniqueID := ans.Image.UniqueID

	if param.SimplePolicyEnable && param.DeployRecordID == 0 && imageUniqueID > 0 {
		// 以快照的方式，如果策略删除了，会重新检测，查询到中间状态是正常的
		brief, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
			ImageUniqueID: imageUniqueID})
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.addSimplePolicyData")
			return err
		}

		for i := range brief {
			if brief[i].SimplePolicy != nil {
				po := brief[i].SimplePolicy.ToPolicy()
				ans.TotalPolicy = append(ans.TotalPolicy, *po)

				if util.ExistBit1(brief[i].Flag, imagesecModel.FlagDetectException) {
					ans.RiskPolicy = append(ans.RiskPolicy, *po)
				}
			}
		}
	}

	if param.SimplePolicyEnable && param.DeployRecordID > 0 && ans.DeployRecord != nil {
		for i := range ans.DeployRecord.TotalPolicy {
			po := ans.DeployRecord.TotalPolicy[i]
			pn := po.ToPolicy()
			ans.TotalPolicy = append(ans.TotalPolicy, *pn)
		}

		for i := range ans.DeployRecord.RiskPolicy {
			po := ans.DeployRecord.RiskPolicy[i]
			pn := po.ToPolicy()
			ans.RiskPolicy = append(ans.RiskPolicy, *pn)
		}
	}

	return nil
}

func (s *ImageInfoMetaSrv) addDetectResultData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	imageID := ans.Image.ID
	imageUniqueID := ans.Image.UniqueID

	if param.DeployRecordID > 0 {
		return nil
	}

	if param.DetectResultEnable && (len(param.DetectParam.SecurityPolicyIds) > 0 || param.DetectParam.AllPolicy) {
		if param.DetectParam.AllPolicy {
			param.DetectParam.SecurityPolicyIds = make([]int64, 0)
		}

		ans.DetectResult = make(map[string][]*imagesecModel.ImageDetectResult)
		detectTypes := param.GetDetectTypes()
		for id := range detectTypes {
			dt := detectTypes[id]
			result, err := s.detectResultDal.SearchDetectResult(ctx, imagesecModel.SearchDetectResultParam{
				ImageUniqueID: imageUniqueID,
				PolicyIds:     param.DetectParam.SecurityPolicyIds,
				DetectType:    dt,
			})
			if err != nil {
				s.Log.Err(err).Int64("imageID", imageID).
					Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchDetectResult")
				return err
			}
			if ans.DetectResult[dt] == nil {
				ans.DetectResult[dt] = make([]*imagesecModel.ImageDetectResult, 0)
			}
			ans.DetectResult[dt] = append(ans.DetectResult[dt], result...)
		}
	}
	return nil
}

func (s *ImageInfoMetaSrv) addScannerInfoData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {

	imageID := ans.Image.ID
	if param.ScanInstanceEnable && ans.Registry != nil {
		ins, err := s.scanInstanceDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{ScannerInstance: ans.Registry.ScannerInstance})
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchScannerInfo")
			return err
		}
		if len(ins) > 0 {
			ans.ScanInstance = &(ins[0])
		}
	}
	return nil
}

func (s *ImageInfoMetaSrv) addCheckDownloadable(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	if !param.CheckDownloadable {
		return nil
	}
	for i := range ans.Sensitive {
		md5 := ans.Sensitive[i].MD5
		filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, md5)
		stat, err := os.Stat(filename)
		if err != nil || stat.IsDir() {
			ans.Sensitive[i].DownloadFilename = ""
		}
	}

	for i := range ans.Malware {
		md5 := ans.Malware[i].Hash
		filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, md5)
		stat, err := os.Stat(filename)
		if err != nil || stat.IsDir() {
			ans.Malware[i].DownloadFilename = ""
		}
	}
	for i := range ans.WebshellView {
		md5 := ans.WebshellView[i].MD5
		filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, md5)
		stat, err := os.Stat(filename)
		if err != nil || stat.IsDir() {
			ans.WebshellView[i].DownloadFilename = ""
		}
	}
	return nil
}

func (s *ImageInfoMetaSrv) addRegistryData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {

	imageID := ans.Image.ID
	if param.RegistryEnable && ans.Image.RegID > 0 {
		registry, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString, ID: ans.Image.RegID})
		if err != nil {
			s.Log.Err(err).Int64("imageID", imageID).
				Str("imageName", ans.Image.GetImageName()).Msg("ImageWithCorrelateData.SearchRegistry")
			return err
		}
		if len(registry) > 0 {
			ans.Registry = &(registry[0])
		}
	}
	return nil
}

func (s *ImageInfoMetaSrv) addRootBootData(ctx context.Context,
	param *imagesecModel.ImageAssociateParam, ans *imagesecModel.ImageWithCorrelateData2) error {
	ans.RootBoot = append(ans.RootBoot, imagesecModel.RootBoot{
		IsRoot:   ans.Image.BootRoot(),
		User:     ans.Image.User,
		UniqueID: ans.Image.UniqueID,
	})

	return nil
}

func (s *ImageInfoMetaSrv) GetImageForDeploy(ctx context.Context, param imagesecModel.DeployMonitorImage) GetImageForDeployRes {
	ans := GetImageForDeployRes{
		Image:   imagesecModel.Image{},
		Exit:    true,
		Scanned: true,
		Err:     nil,
	}
	if param.ImageUUID <= 0 {
		im := imagesecModel.Image{
			ImageName: param.Image,
			Digest:    param.Digest,
		}
		param.ImageUUID = im.GenUUID()
	}
	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UUIDs: []uint32{param.ImageUUID}})
	if err != nil {
		ans.Err = err
		return ans
	}
	if len(images) == 0 {
		ans.Exit = false
		return ans
	}
	// 找一个扫描完成的镜像
	for i := range images {
		image := images[i]
		ans.Image = *image
		subtaskParam := imagesecModel.SearchTaskParam{
			ImageUniqueID: image.UniqueID,
			ScanStatus:    []int64{imagesecModel.TaskStatusDetectFinished},
			Filter:        imagesecModel.EmptyFilter().SetSortDesc().SetSortFiledByID().SetLimit(1)}

		subtasks, _, err := s.scanTaskDal.SearchScanSubtask(ctx, subtaskParam)
		if err != nil {
			ans.Err = err
			return ans
		}
		if len(subtasks) > 0 {
			return ans
		}
	}
	ans.Scanned = false
	return ans
}

type GetImageForDeployRes struct {
	Image         imagesecModel.Image
	Exit          bool
	Scanned       bool
	Err           error
	CorrelateData imagesecModel.ImageWithCorrelateData2
}

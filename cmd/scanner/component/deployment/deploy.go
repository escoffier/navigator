package deployment

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/deployment/detector"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *DeploySrv) GetImageDataForDeploy(ctx context.Context, param imagesecModel.DeployMonitorImage) imagesecModel.ImageDataForDeployRes {

	ans := imagesecModel.ImageDataForDeployRes{
		CorrelateData: &imagesecModel.ImageWithCorrelateData2{},
		Exit:          false,
		Scanned:       false,
		Errs:          make([]error, 0),
	}
	if param.Digest == "" {
		ans.Exit = false
		ans.Scanned = false
		return ans
	}

	if param.ImageUUID <= 0 {
		im := imagesecModel.Image{
			ImageName: param.Image,
			Digest:    param.Digest,
		}
		param.ImageUUID = im.GenUUID()
	}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
		UUIDs:         []uint32{param.ImageUUID},
		Digests:       []string{param.Digest},
		ImageFromType: imagesecModel.ImageFromRegistry,
	})
	if err != nil {
		ans.Errs = append(ans.Errs, err)
		return ans
	}
	if len(images) > 0 {
		ans.Exit = true
	}
	// 找一个扫描完成的镜像
	for i := range images {
		image := images[i]
		ans.CorrelateData.Image = *image
		subtaskParam := imagesecModel.SearchTaskParam{
			ImageUniqueID: image.UniqueID,
			ScanStatus:    []int64{imagesecModel.TaskStatusDetectFinished},
			Filter:        model.EmptyFilter().SetSortDesc().SetSortFiledByID().SetLimit(1)}

		subtasks, _, err := s.scanTaskDal.SearchScanSubtask(ctx, subtaskParam)
		if err != nil {
			ans.Errs = append(ans.Errs, err)
			continue
		}
		if len(subtasks) > 0 {
			ans.Scanned = true
			break
		}
	}

	if ans.Exit && len(ans.Errs) == 0 {
		data, err := s.ImageService.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
			ImageFromType:      imagesecModel.ImageFromRegistry,
			ImageUniqueID:      ans.CorrelateData.Image.UniqueID,
			VulnEnable:         true,
			MalwareEnable:      true,
			EnvEnable:          true,
			PkgEnable:          true,
			LicenseEnable:      true,
			ImageLicenseEnable: true,
			SensitiveEnable:    true,
			WebshellEnable:     true,
			SubtaskEnable:      true,
			BaseImageEnable:    true,
			TrustedEnable:      true,
			ImageInReg:         true,
		})
		if err != nil {
			ans.Errs = append(ans.Errs, err)
		}
		if err == nil {
			ans.CorrelateData = data
		}
	}

	return ans
}
func NeedAddDetectSubtask(image imagesecModel.DeployMonitorImage, policy *imagesecModel.SecurityPolicy) bool {
	if policy == nil {
		return false
	}
	if policy.PolicyType != imagesecModel.ConfigTypeDeploy {
		return false
	}
	if !policy.Enable {
		return false
	}

	// 所有的正则都只要包含就行
	for i := range policy.Scope.ImageRegexp {
		reg := policy.Scope.ImageRegexp[i]
		if reg != "" {
			compile, err := regexp.Compile(reg)
			if err != nil {
				continue
			}
			if compile.FindString(image.Image) != "" {
				return true
			}
		}
	}

	return false
}

func (s *DeploySrv) CheckDeploy(ctx context.Context, param imagesecModel.DeployMonitorImage) bool {
	param.Image = strings.TrimSpace(param.Image)
	host, repo, tag := scannerUtils.ParseImageName(param.Image)
	param.Repo, param.Tag, param.Host = repo, tag, host

	if param.Empty() {
		return true
	}
	param.ImageUUID = param.GenImageUUID()

	s.Log.Info().Interface("param", param).Msg("CheckDeploy start")

	res := s.GetImageDataForDeploy(ctx, param)

	record := imagesecModel.DeployRecord{
		ImageUUID:      param.ImageUUID,
		ImageName:      param.Image,
		Digest:         param.Digest,
		Host:           host,
		Repo:           repo,
		Tag:            tag,
		VulnIssue:      make([]imagesecModel.DeployIssue, 0),
		MalwareIssue:   make([]imagesecModel.DeployIssue, 0),
		WebshellIssue:  make([]imagesecModel.DeployIssue, 0),
		SensitiveIssue: make([]imagesecModel.DeployIssue, 0),
		PkgIssue:       make([]imagesecModel.DeployIssue, 0),
		LicenseIssue:   make([]imagesecModel.DeployIssue, 0),
		EnvIssue:       make([]imagesecModel.DeployIssue, 0),
		RootBootIssue:  make([]imagesecModel.DeployIssue, 0),
		BaseImageIssue: make([]imagesecModel.DeployIssue, 0),
		RiskPolicy:     make([]imagesecModel.SimplePolicy, 0),
		TotalPolicy:    make([]imagesecModel.SimplePolicy, 0),
	}

	if res.Exit {
		record.ImageUniqueID = res.CorrelateData.Image.UniqueID
		record.Image = res.CorrelateData.Image
	} else {
		record.Image = imagesecModel.Image{
			Host:      host,
			Repo:      repo,
			Tag:       tag,
			ImageName: fmt.Sprintf("%s/%s:%s", host, repo, tag),
			Digest:    param.Digest,
			ImageUUID: param.ImageUUID,
		}
	}

	pos, _, err := s.detectPolicyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{PolicyType: imagesecModel.ConfigTypeDeploy})
	if err != nil {
		s.Log.Err(err).Msg("CheckWhite")
		return true
	}
	policy := make([]*imagesecModel.SecurityPolicy, 0)

	for i := range pos {
		if NeedAddDetectSubtask(param, pos[i]) {
			policy = append(policy, pos[i])
		}
	}
	det := make(map[string]map[uint64]*imagesecModel.ImageDetectResult)

	for i := range policy {
		po := policy[i]
		var sinFlag uint64
		if !detector.CheckImageExit(ctx, res, po) {
			sinFlag = util.SetBit1(sinFlag, imagesecModel.FlagImageDetectNotExitINReg)
			sinFlag = util.SetBit1(sinFlag, imagesecModel.FlagImageDeployBlock)
		}
		if !detector.CheckImageScanned(ctx, res, po) && res.Exit {
			sinFlag = util.SetBit1(sinFlag, imagesecModel.FlagImageNotScanned)
			sinFlag = util.SetBit1(sinFlag, imagesecModel.FlagImageDeployBlock)
		}
		if detector.CheckImageHasErr(ctx, res, po) {
			// 内部出错，不可阻断，也不记录
			return true
		}

		if res.Exit {
			sin := s.ImagePolicyChecker.Check(ctx, res.CorrelateData, po)
			det = detect.MergeDetectResult(det, sin)
			// 这里的 flag 包含的信息不全，不优雅
			sinFlag = util.SetBit1(sinFlag, GenPolicyActionFlag(sin))
		}

		sim := imagesecModel.SimplePolicy{UniqueID: po.UniqueID, Name: po.Name, Flag: sinFlag, ID: po.ID}

		record.TotalPolicy = append(record.TotalPolicy, sim)
		if util.ExistBit1(sim.Flag, imagesecModel.FlagImageDeployBlock) ||
			util.ExistBit1(sim.Flag, imagesecModel.FlagImageDeployAlarm) {
			record.RiskPolicy = append(record.RiskPolicy, sim)
		}
	}

	// 镜像本身flag
	preFlag, flag := res.CorrelateData.Image.Flag, record.Flag
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagAppImage)
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagBaseImage)
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagImageNotMaintained)
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagImageHasUnknownVun)
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagImageHasLowVuln)
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagImageHasMediumVuln)
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagImageHasHighVuln)
	flag = compareAndSetFlag(preFlag, flag, imagesecModel.FlagImageHasCriticalVuln)

	// 阻断问题列表flag(和镜像列表 flag 类似) 主要用于筛选
	flag = detect.GenImageIssueFlag(det, flag)

	// 如果是未扫描和不在仓库中
	for i := range record.TotalPolicy {
		po := record.TotalPolicy[i]
		if util.ExistBit1(po.Flag, imagesecModel.FlagImageDetectNotExitINReg) {
			flag = util.SetBit1(flag, imagesecModel.FlagImageDetectNotExitINReg)
		}
		if util.ExistBit1(po.Flag, imagesecModel.FlagImageNotScanned) {
			flag = util.SetBit1(flag, imagesecModel.FlagImageNotScanned)
		}
		if util.ExistBit1(po.Flag, imagesecModel.FlagImageDeployBlock) {
			flag = util.SetBit1(flag, imagesecModel.FlagImageDeployBlock)
		}
	}
	record = AddIssueDeployRecord(record, det)
	white, err := s.CheckWhite(ctx, param)
	if err != nil {
		s.Log.Err(err).Msg("CheckWhite")
		return true
	}
	if err == nil && white {
		flag = util.SetBit1(flag, imagesecModel.FlagImageDeployWhite)
		flag = util.SetBit1(flag, imagesecModel.FlagImageDeployPassed)
		flag = util.SetBit0(flag, imagesecModel.FlagImageDeployBlock)
		flag = util.SetBit0(flag, imagesecModel.FlagImageDeployAlarm)
	}

	act := GenAction(det, flag)
	record.Action = act
	record.Flag = flag

	if err := s.CreateDeployRecord(ctx, &record); err != nil {
		s.Log.Err(err).Msg("CheckDeploy CreateDeployRecord")
	}

	s.Log.Info().Interface("param", param).Str("action", act).
		Msg("CheckDeploy end")

	return record.Action != imagesecModel.DeployActionBlock
}

func AddIssueDeployRecord(record imagesecModel.DeployRecord, det map[string]map[uint64]*imagesecModel.ImageDetectResult) imagesecModel.DeployRecord {
	for k, v := range det {
		switch k {
		case imagesecModel.DetectTypeVulnRule:
			for _, d := range v {
				record.VulnIssue = append(record.VulnIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypeSensRule:
			for _, d := range v {
				record.SensitiveIssue = append(record.SensitiveIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypeMalwareRule:
			for _, d := range v {
				record.MalwareIssue = append(record.MalwareIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypePkgRule:
			for _, d := range v {
				record.PkgIssue = append(record.PkgIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypeWebshellRule:
			for _, d := range v {
				record.WebshellIssue = append(record.WebshellIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypeRootRule:
			for _, d := range v {
				record.RootBootIssue = append(record.RootBootIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypeEnvRule:
			for _, d := range v {
				record.EnvIssue = append(record.EnvIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypeBaseImageRule:
			for _, d := range v {
				record.BaseImageIssue = append(record.BaseImageIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}

		case imagesecModel.DetectTypeTrustedImageRule:
			for _, d := range v {
				record.TrustedImageIssue = append(record.TrustedImageIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}
		case imagesecModel.DetectTypeLicenseRule:
			for _, d := range v {
				record.LicenseIssue = append(record.LicenseIssue, imagesecModel.DeployIssue{
					Target: d.UniqueTarget,
					Flag:   d.Flag,
				})
			}
		}
	}
	return record
}

func (s *DeploySrv) CheckWhite(ctx context.Context, res imagesecModel.DeployMonitorImage) (bool, error) {
	image, _, err := s.DeployRecordDal.SearchDeployWhiteImage(ctx, imagesecModel.SearchDeployWhiteImageParam{})
	if err != nil {
		s.Log.Err(err).Msg("SearchDeployWhiteImage")
		return true, err
	}
	for i := range image {
		im := image[i]
		if im.ExpirationAt < time.Now().UnixMilli() {
			continue
		}
		compile, err := regexp.Compile(im.ImageName)
		if err != nil {
			s.Log.Err(err).Str("image", im.ImageName).Msg("Compile")
			continue
		}
		findString := compile.FindString(res.Image)
		if findString != "" {
			return true, nil
		}
	}
	return false, nil
}

func compareAndSetFlag(pre, flag uint64, base uint64) uint64 {
	if util.ExistBit1(pre, base) {
		flag = util.SetBit1(flag, base)
	} else {
		flag = util.SetBit0(flag, base)
	}
	return flag
}

// 检测完成获取是否阻断的 action
func GenAction(det map[string]map[uint64]*imagesecModel.ImageDetectResult, imageFlag uint64) string {

	if util.ExistBit1(imageFlag, imagesecModel.FlagImageDeployWhite) {
		return imagesecModel.DeployActionPass
	}
	if util.ExistBit1(imageFlag, imagesecModel.FlagImageDeployBlock) {
		return imagesecModel.DeployActionBlock
	}

	hasAlarm := false
	for _, res := range det {
		for k := range res {
			if util.ExistBit1(res[k].Flag, imagesecModel.FlagDetectDeployActionBlock) {
				return imagesecModel.DeployActionBlock
			}
			if util.ExistBit1(res[k].Flag, imagesecModel.FlagDetectDeployActionAlarm) {
				hasAlarm = true
			}
		}
	}
	if hasAlarm {
		return imagesecModel.DeployActionAlarm
	}
	return imagesecModel.DeployActionPass
}

// 单个策略检测后的 flag 标签
func GenPolicyActionFlag(det map[string][]*imagesecModel.ImageDetectResult) uint64 {
	hasAlarm := false
	for _, res := range det {
		for k := range res {
			if util.ExistBit1(res[k].Flag, imagesecModel.FlagDetectDeployActionBlock) {
				return imagesecModel.FlagImageDeployBlock
			}
			if util.ExistBit1(res[k].Flag, imagesecModel.FlagDetectDeployActionAlarm) {
				hasAlarm = true
			}
		}
	}
	if hasAlarm {
		return imagesecModel.FlagImageDeployAlarm
	}
	return imagesecModel.FlagImageDeployPassed
}

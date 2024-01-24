package libimagetask

import (
	"context"
	"fmt"
	"os"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

func (s *RegImageScanQueue) BuildScanTask(ctx context.Context,
	subtask *imagesecModel.ImageScanSubTask,
	imageData *imagesecModel.ImageWithCorrelateData2,
) (imagesecTypes.ScanSubTask, error) {
	sub := imagesecTypes.ScanSubTask{}

	// 查询缓存
	imageLayer := make([]string, 0)
	// 这一步主要是为了加漏洞的缓存
	imageLayer = append(imageLayer, imageData.Image.Digest)

	for _, ly := range imageData.Image.Layer {
		imageLayer = append(imageLayer, ly.Digest)
	}

	ans := make([]string, 0)
	rule, _, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, imagesecModel.SearchSensitiveRuleParam{
		RuleType:  imagesecModel.SensitiveRuleTypeFilename,
		Enable:    consts.TrueString,
		IsDefault: consts.FalseString,
		Filed:     []string{"id", "value"},
	})
	if err != nil {
		s.Log.Err(err).Msg("ScanImageQueue SearchAllSensitiveRule")
		return sub, err
	}
	for i := range rule {
		ans = append(ans, rule[i].Value)
	}

	// 加缓存
	cacheLayer, _ := s.ScanResultDal.SearchScanLayerData(ctx, imagesecModel.SearchScanLayerParam{Layers: imageLayer})
	config, err := s.scanImageConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err != nil {
		s.Log.Err(err).Msg("GetScanImageConfig")
		return sub, err
	}
	ver, err := s.GetDBVersion(ctx)
	if err != nil {
		return sub, err
	}

	// 查询配置
	// 为啥要实时查呢，因为配置更新之后要快速感知
	// 可以在程序中缓存
	ses := s.SearchAllSensitiveRule(ctx)

	// 病毒和 webshell暂时使用发版本的版本号

	typesSubTask := s.modelToType(subtask, imageData, ses, config.ImageScanConfig, ver, cacheLayer)

	return typesSubTask, nil
}

func (s *RegImageScanQueue) GetDBVersion(ctx context.Context) (imagesecTypes.RuleVersion, error) {
	ver := imagesecTypes.RuleVersion{
		Sensitive: global.SenstiveVer,
		Vuln:      global.VulnVer,
		Webshell:  scannerUtils.GetSoftVersion(),
		Avira:     scannerUtils.GetSoftVersion(),
		License:   scannerUtils.GetSoftVersion(),
	}

	filter := imagesecModel.EmptyFilter().SetSortDesc().SetSortFiled("created_at").SetLimit(1)

	if global.VulnVer == "" {
		vulnVer, _, err := s.dbMetaDal.SearchScanDbMeta(ctx, imagesecModel.SearchScanDbParam{DBType: consts.TrivyName, Filter: filter})
		if err != nil {
			s.Log.Err(err).Msg("ScanImageQueue SearchScanDbMeta")
			return ver, err
		}
		if len(vulnVer) == 0 {
			return ver, fmt.Errorf("not get vulndb version")
		}
		ver.Vuln = vulnVer[0].DBVersion
		global.VulnVer = vulnVer[0].DBVersion
	}

	if global.SenstiveVer == "" {
		sensVer, _, err := s.dbMetaDal.SearchScanDbMeta(ctx, imagesecModel.SearchScanDbParam{DBType: imagesecModel.SensitiveCacheData, Filter: filter})
		if err != nil {
			s.Log.Err(err).Msg("ScanImageQueue SearchScanDbMeta")
			return ver, err
		}
		if len(sensVer) == 0 {
			return ver, fmt.Errorf("not get sensitive version")
		}
		ver.Sensitive = sensVer[0].DBVersion
		global.SenstiveVer = sensVer[0].DBVersion
	}

	return ver, nil
}

func (s *RegImageScanQueue) modelToType(
	subtask *imagesecModel.ImageScanSubTask,
	data *imagesecModel.ImageWithCorrelateData2,
	ses []string,
	config *imagesecModel.ImageScanConfig,
	ver imagesecTypes.RuleVersion,
	cache []*imagesecModel.ScanLayerData,
) imagesecTypes.ScanSubTask {
	sub := imagesecTypes.ScanSubTask{
		TaskID:        subtask.TaskID,
		SubTaskID:     subtask.ID,
		NodeInfo:      imagesecTypes.NodeInfo{},
		NodeImageMeta: imagesecTypes.ImageMeta{},
		RegImageMeta: imagesecTypes.ScanImageMeta{
			ImageUUID: data.Image.ImageUUID,
			UniqueID:  data.Image.UniqueID,
			Host:      data.Image.Host,
			Digest:    data.Image.Digest,
			Repo:      data.Image.Repo,
			Tag:       data.Image.Tag,
		},
		ScanInstance:   imagesecTypes.ScanInstance{},
		RegInfo:        imagesecTypes.RegInfo{},
		SensitiveRules: ses,
		DBVersion:      ver,
		UniqueID:       "",
		ScanTimeout:    0,
		WebshellCache:  make(imagesecTypes.LayerInCache),
		VulnCache:      make(imagesecTypes.LayerInCache),
		LicenseCache:   make(imagesecTypes.LayerInCache),
		SensitiveCache: make(imagesecTypes.LayerInCache),
		MalwareCache:   make(imagesecTypes.LayerInCache),
		DeepScan:       false,
		MalwareScanAll: s.Config.MalWareScanAll,
	}
	if config != nil {
		sub.ScanTimeout = config.ScanTimeout
		sub.DeepScan = config.DeepScan
	}

	if data.ScanInstance != nil {
		sub.ScanInstance = imagesecTypes.ScanInstance{
			ClusterKey:      data.ScanInstance.ClusterKey,
			ClusterName:     data.ScanInstance.ClusterName,
			ScannerPodID:    data.ScanInstance.ScannerPodID,
			ScannerInstance: data.ScanInstance.ScannerInstance,
			ScannerVersion:  data.ScanInstance.ScannerVersion,
		}
	}
	if data.Registry != nil {
		sub.RegInfo = imagesecTypes.RegInfo{
			Name:     data.Registry.Name,
			RegID:    data.Registry.ID,
			Url:      data.Registry.Url,
			Username: data.Registry.Username,
			Password: data.Registry.PasswordString,
		}
	}

	sub.UniqueID = sub.GenUniqueID()
	// 加缓存
	// 先判断漏洞，敏感文件是否需要加缓存
	// 加一个环境变量，便于测试
	version := map[string]string{
		imagesecModel.VulnCacheData:      ver.Vuln,
		imagesecModel.SensitiveCacheData: ver.Sensitive,
		imagesecModel.WebshellCacheData:  ver.Webshell,
		imagesecModel.MalwareCacheData:   ver.Avira,
		imagesecModel.LicenseCacheData:   ver.License,
	}

	if os.Getenv("SCAN_NOT_USE_CACHE") != consts.TrueString {
		for i := range cache {
			ca := cache[i]
			if ca.DbVersion != version[ca.Issue] {
				continue
			}
			switch ca.Issue {
			case imagesecModel.VulnCacheData:
				sub.VulnCache[ca.Layer] = true // 对于漏洞来说，这里的 layer 就是镜像的 digest
			case imagesecModel.WebshellCacheData:
				sub.WebshellCache[ca.Layer] = true
			case imagesecModel.MalwareCacheData:
				// 默认情况下病毒不会扫描全部文件，测试的情况下会全部开启，此时就不能使用缓存
				if !s.Config.MalWareScanAll {
					sub.MalwareCache[ca.Layer] = true
				}
			case imagesecModel.SensitiveCacheData:
				sub.SensitiveCache[ca.Layer] = true
			case imagesecModel.LicenseCacheData:
				sub.LicenseCache[ca.Layer] = true
			}
		}
	}

	return sub
}

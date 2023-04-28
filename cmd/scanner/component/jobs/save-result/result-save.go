package saveresult

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/imroc/req/v3"
	"gitlab.com/security-rd/go-pkg/logging"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	boltvuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/bolt-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultSave struct {
	ImageDal           store.ImageDal
	VulnBoltDal        boltvuln.VulnBoltDal
	VulnDal            store.VulnDalInterface
	ImageScanResultDal store.ImageScanResultDal
}

func IsKernelPkg(pkg ftypes.Package) bool {
	if pkg.SrcName == "kernel" || pkg.SrcName == "linux" {
		return true
	}
	return false
}

func (sv *ScanResultSave) AddVulnMeta(ctx context.Context, cevVuln *model.Vuln) *model.Vuln {
	cnvd, cnnvd, err := sv.VulnBoltDal.GetVulnDetail(cevVuln.Name)

	if err != nil {
		logging.Get().Err(err).Str("vulnName", cevVuln.Name).Msg("AddVulnMeta")
		return cevVuln
	}

	cevVuln.CnnvdName = cnnvd.Number
	if cevVuln.Metadata == nil {
		cevVuln.Metadata = &model.VulnMatedata{}
	}
	cevVuln.Metadata.CNNVDs = cnnvd
	cevVuln.Metadata.CNVDs = cnvd
	return cevVuln
}

func (sv *ScanResultSave) GenSeverityHistogram(ctx context.Context, vulns []*model.Vuln) model.SeverityHistogramInfo {
	ret := model.SeverityHistogramInfo{}

	for _, vuln := range vulns {
		switch vuln.Severity {
		case model.SeverityCRITICALString:
			ret.NumCritical++
		case model.SeverityHIGHString:
			ret.NumHigh++
		case model.SeverityMEDIUMString:
			ret.NumMedium++
		case model.SeverityLOWString:
			ret.NumLow++
		case model.SeverityUNKNOWNString:
			ret.NumUnknown++
		}
	}

	return ret
}

func (sv *ScanResultSave) UpdateImageFlag(ctx context.Context, imageID int64, flag uint64) error {
	updater := map[string]interface{}{"flag": flag}
	err := sv.ImageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", imageID), updater, nil)
	return err
}

func (sv *ScanResultSave) UpdateImageOs(ctx context.Context, os *ftypes.OS, imageID int64) error {
	if os == nil {
		return fmt.Errorf("not get os info for image:%d", imageID)
	}

	bys, err := json.Marshal(os)
	if err != nil {
		return err
	}
	update := map[string]interface{}{"os": string(bys)}
	// pkg/detector/ospkg/ubuntu/ubuntu.go
	image, _, err := sv.ImageDal.SearchImage(ctx, store.SearchImageParam{InIds: []int64{imageID}, Fields: []string{"id", "flag"}}, nil)
	if err != nil {
		return err
	}
	if len(image) == 0 {
		return fmt.Errorf("not find image:%d", imageID)
	}
	flag := image[0].Flag

	if os.Eosl {
		flag = util.SetBit1(flag, model.FlagImageNotMaintained)
	} else {
		flag = util.SetBit0(flag, model.FlagImageNotMaintained)
	}
	update["flag"] = flag
	if err := sv.ImageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", imageID), update, nil); err != nil {
		return err
	}
	return nil
}

func (sv *ScanResultSave) UpdateRiskCacheEntry(ctx context.Context, key string, da model.ImageSeverityScore) error {
	data := model.ImageRiskOverRedis{
		Key:  key,
		Data: da,
	}
	if err := sv.SetRedisData(ctx, data); err != nil {
		logging.Get().Err(err).Msg("updateRiskVulnCacheEntry SetRedisData")
		return err
	}
	logging.Get().Info().Interface("data", da).Msg("UpdateRiskCacheEntry")
	return nil
}

func (sv *ScanResultSave) SetRedisData(ctx context.Context, data model.ImageRiskOverRedis) error {
	if !data.Valid() {
		logging.Get().Info().Interface("data", data).Msg("SetRedisData")
		return fmt.Errorf("data not valid")
	}

	logging.Get().Debug().Interface("data", data).Msg("SetRedisData")

	consoleURL := os.Getenv("CONSOLE_EXTERNAL_URL")
	if consoleURL == "" {
		logging.Get().Err(fmt.Errorf("not get CONSOLE_EXTERNAL_URL")).Msg("SetRedisData")
		return fmt.Errorf("not find CONSOLE_EXTERNAL_URL")
	}

	url := fmt.Sprintf("%s%s", consoleURL, "/api/openapi/scanner/vulns/setVulnRisk")
	logging.Get().Debug().Str("url", url).Msg("SetRedisData")

	client := req.C().SetTimeout(10 * time.Minute)

	resp, err := client.R().SetHeader(consts.ScannerUser, consts.InternalApiKey).SetBody(data).Post(url)

	if err != nil {
		logging.Get().Err(err).Str("url", url).Msg("SetRedisData")
		return err
	}
	if !resp.IsSuccess() {
		logging.Get().Err(err).Str("url", url).Int("httpcode", resp.GetStatusCode()).Msg("SetRedisData")
		return fmt.Errorf("SetRedisData not success")
	}
	logging.Get().Info().Str("url", url).Msg("SetRedisData  success ")
	return nil
}

func NewScanResultSave() *ScanResultSave {
	vu := &ScanResultSave{
		ImageDal:           store.GetScannerOrmDb(),
		VulnBoltDal:        boltvuln.GetSingleBoltVuln(),
		VulnDal:            store.GetSingeVulnDao(),
		ImageScanResultDal: store.GetSingeScanResultDAO(),
	}
	return vu
}

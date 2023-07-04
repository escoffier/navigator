package detect

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

const (
	serviceName = "image-detect-srv"
)

type ImageDetect struct {
	detectSrv *detect.Detector
}

func (s *ImageDetect) Start(ctx context.Context) error {
	s.detectSrv.Start(ctx)
	logging.Get().Info().Str("serviceName", serviceName).Msg("start success")
	return nil
}

func (s *ImageDetect) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("int service err")
		return
	}
	logging.Get().Info().Str("serviceName", serviceName).Msg("register success")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	scannerWrapperDb := store.GetScannerWrapperDb()

	registryDal := store.NewRegistryDao(scannerWrapperDb)
	nodeScanResultDal := imagesecStore.NewScanResultDao(scannerWrapperDb)
	nodeImageDal := imagesecStore.NewImageMetaDao(scannerWrapperDb, nil)
	resourceDal := store.NewResourceDao(scannerWrapperDb)
	trustedImageDal := store.NewScannerOrm(scannerWrapperDb)

	policyDal := imagesecStore.NewDetectPolicyDao(scannerWrapperDb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(scannerWrapperDb)
	sensitiveRuleDal := imagesecStore.NewSensitiveRuleDao(scannerWrapperDb)
	nodeReportDal := imagesecStore.NewNodeReportDao(scannerWrapperDb)
	scannerConfigDal := imagesecStore.NewScannerConfigDao(scannerWrapperDb)
	imagePolicyChecker := detect.NewImagePolicyCheck()
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(scannerWrapperDb)

	imageDataSrv := imagemeta.NewNodeImageSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal, scannerConfigDal, nodeScanTaskDal)

	imagePolicySrv := imagesecSrv.NewPolicySrv(policyDal, nil, sensitiveRuleDal)

	nodeImageSvc := imagemeta.NewNodeImageSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal, scannerConfigDal, nodeScanTaskDal)

	detectTaskDal := imagesecStore.NewDetectTaskDao(scannerWrapperDb)

	detectTaskSrv := detect.NewImageDetectTaskSrv(nodeImageSvc, detectTaskDal, policyDal)

	p := &ImageDetect{
		detectSrv: detect.NewDetector(imagePolicySrv, detectResultDal, nodeScanTaskDal, detectTaskDal,
			imageDataSrv, imagePolicyChecker, nodeImageDal, detectTaskSrv),
	}

	return p, nil
}

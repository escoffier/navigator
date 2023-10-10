package detect

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
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
	rdbInstance := store.GetRDBInstance()

	registryDal := imagesecStore.NewRegistryDao(rdbInstance)
	nodeScanResultDal := imagesecStore.NewScanResultDao(rdbInstance)
	nodeImageDal := imagesecStore.NewImageMetaDao(rdbInstance, nil)
	resourceDal := imagesecStore.NewResourceDao(rdbInstance)
	trustedImageDal := store.NewScannerOrm(rdbInstance)
	scanInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)
	policyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	detectResultDal := imagesecStore.NewImageDetectResultDao(rdbInstance)
	sensitiveRuleDal := imagesecStore.NewSensitiveRuleDao(rdbInstance)
	userDal := imagesecStore.NewUserDao(rdbInstance)
	nodeReportDal := imagesecStore.NewNodeReportDao(rdbInstance)
	scannerConfigDal := imagesecStore.NewScanImageConfigDao(rdbInstance)
	imagePolicyChecker := detect.NewImagePolicyCheck()
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(rdbInstance)
	deployDal := imagesecStore.NewDeployDao(rdbInstance)
	cacheDal := imagesecStore.NewImageCacheDao(rdbInstance)

	imageDataSrv := imagemeta.NewImageMetaSrv(
		nodeImageDal,
		registryDal,
		nodeScanResultDal,
		resourceDal,
		nodeReportDal,
		policyDal,
		detectResultDal,
		trustedImageDal,
		scannerConfigDal,
		nodeScanTaskDal,
		scanInstanceDal,
		deployDal,
		cacheDal,
	)

	imagePolicySrv := imagesec.NewPolicySrv(policyDal, nil, sensitiveRuleDal, userDal)

	detectTaskDal := imagesecStore.NewDetectTaskDao(rdbInstance)

	detectTaskSrv := detect.NewImageDetectTaskSrv(imageDataSrv, detectTaskDal, policyDal, detectResultDal)

	p := &ImageDetect{
		detectSrv: detect.NewDetector(imagePolicySrv, detectResultDal, nodeScanTaskDal, detectTaskDal,
			imageDataSrv, imagePolicyChecker, nodeImageDal, detectTaskSrv),
	}

	return p, nil
}

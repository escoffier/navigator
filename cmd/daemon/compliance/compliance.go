package compliance

import (
	"fmt"
	"math/rand"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/compliance/cri"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/compliance/host"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/compliance/kube"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

type ScanProvider interface {
	InitConfig() error
	MappingBenchmarkVersion() error
	Run() error
}

func StartComplianceScan(typ model.ComplianceCheckType, mqWriter mq.Writer, taskId, clusterId, nodeName string, checkList []string) error {
	var p ScanProvider
	switch typ {
	case model.ComplianceCheckTargetTypeKube:
		opt := kube.NewKubeOptions(taskId, clusterId, nodeName, mqWriter, kube.CheckList(checkList))
		p = kube.NewKube(opt)
	case model.ComplianceCheckTargetTypeCRI:
		opt := cri.NewCriOptions(taskId, clusterId, nodeName, mqWriter, cri.CheckList(checkList))
		p = cri.NewCri(opt)
	case model.ComplianceCheckTargetTypeHost:
		opt := host.NewHostOptions(taskId, clusterId, nodeName, mqWriter, host.CheckList(checkList))
		p = host.NewHost(opt)
	default:
		return fmt.Errorf("unsupported check type: [%s]", typ)
	}

	err := p.InitConfig()
	if err != nil {
		return err
	}

	if err = p.MappingBenchmarkVersion(); err != nil {
		logging.Get().Error().Err(err).Msg("")
		return err
	}

	// 异步运行扫描
	go func() {
		defer func() {
			if rc := recover(); rc != nil {
				logging.Get().Error().Msgf("recover: %v", rc)
			}
		}()

		// 等待一下再开始运行
		time.Sleep(time.Second * time.Duration(3+rand.Intn(10)))
		if err = p.Run(); err != nil {
			logging.Get().Error().Err(err).Msg("")
		}
	}()

	return nil
}

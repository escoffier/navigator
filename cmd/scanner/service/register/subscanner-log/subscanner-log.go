package subscannerlog

import (
	"context"
	"encoding/json"
	"os"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

const (
	serviceName = "subscanner-log-service"
)

type Config struct {
}

type SubScannerLogService struct { // nolint
	Reader mq.Reader
}

func (s *SubScannerLogService) getDao(name string) store.SubScannerInterface {
	if name == "version" {
		return store.GetSingeVersionDao()
	}
	return nil
}

func (s *SubScannerLogService) dispatchSql(ctx context.Context, data scannermodel.SubScannerToMainSql) error {
	dal := s.getDao(data.DalName)
	if dal == nil {
		def := store.GetRDBInstance()
		if data.Action == scannermodel.SubSqlUpdate {
			err := def.Get().Model(data.Data).Updates(data.Data).Omit("id").Error // 不指定dal的情况下需要谨慎使用
			if err != nil {
				logging.Get().Err(err).Msg("default update error check data")
				return err
			}
		}
		if data.Action == scannermodel.SubSqlCreate {
			err := def.Get().Model(data.Data).Create(data.Data).Error // 不指定dal的情况下需要谨慎使用
			if err != nil {
				logging.Get().Err(err).Msg("default create error check data")
				return err
			}
		}
	} else {
		if data.Action == scannermodel.SubSqlUpdate {
			err := dal.Update(ctx, data.Data, data.Params)
			if err != nil {
				logging.Get().Err(err).Msgf("%v dao update error check data", data.DalName)
				return err
			}
		}
		if data.Action == scannermodel.SubSqlCreate {
			err := dal.Create(ctx, data.Data, nil)
			if err != nil {
				logging.Get().Err(err).Msgf("%v dao create error check data", data.DalName)
				return err
			}
		}
	}
	return nil
}

func (s *SubScannerLogService) handle(ctx context.Context, msg kafka.Message) error {
	sqlData := scannermodel.SubScannerToMainSql{}
	err := json.Unmarshal(msg.Value, &sqlData)
	if err != nil {
		logging.Get().Err(err).Msg("unmarshal sqlData error")
		return err
	}
	logging.Get().Info().Msgf("get value %v", sqlData)
	err = s.dispatchSql(ctx, sqlData)
	if err != nil {
		logging.Get().Err(err).Msg("subScannerLog handle error")
		return err
	}
	return nil
}

func (s *SubScannerLogService) Start(ctx context.Context) error {

	isMain := os.Getenv("IS_MAIN_CLUSTER")
	if isMain != consts.TrueString {
		logging.Get().Info().Msg("not in main cluster")
		return nil
	}
	err := s.Reader.Subscribe(scannermodel.SubScannerKafkaTopic, scannermodel.SubScannerKafkaGroupID, s.handle)
	if err != nil {
		logging.Get().Err(err).Msg("subScannerLog subscribe error")
		return err
	}
	return nil
}

func (s *SubScannerLogService) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	c := &SubScannerLogService{}
	reader, err := mq.GetClientFactory().Reader(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("init subScanner log reader error")
		return nil, err
	}
	c.Reader = reader
	return c, nil
}

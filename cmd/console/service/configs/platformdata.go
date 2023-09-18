package configs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	ErrServiceNotReady  = errors.New("service not ready")
	ErrInvalidTTL       = fmt.Errorf("invalid ttl")
	ErrInvalidWaterline = fmt.Errorf("invalid waterline")
)

type DataConfigOperator struct {
	dataService *data.Service
	Aperator    string
}

func (c *DataConfigOperator) GetAperator() string {
	return c.Aperator
}

func (c *DataConfigOperator) SetAperator(username string) {
	c.Aperator = username
}

func (dco *DataConfigOperator) Export(ctx context.Context) ([]byte, error) {
	config := make(map[string]int)

	dataService, ok := data.GetService(ctx)
	if !ok {
		logging.Get().Error().Msgf("service not ready")
		return nil, errors.New("service not ready")

	}
	// 获取该模块的配置项 --- 分别写到各模块的service中(暂定)
	List := dataService.GetConfigList()
	for _, value := range List {
		if value == "waterline" {
			percentage, err := dataService.GetDataWaterline(ctx)
			if err != nil {
				logging.Get().Error().Msgf("couldn't get waterline: %w", err)
				return nil, errors.New("couldn't get waterline")
			}
			config[value] = percentage
		} else {
			dataTTL, err := dataService.GetDataTTL(ctx, value)
			if err != nil {
				logging.Get().Error().Msgf("couldn't get data tll: %w", err)
				return nil, errors.New("couldn't get data tll")

			}
			config[value] = dataTTL
		}
	}

	jsondata, err := json.Marshal(config)
	if err != nil {
		logging.Get().Error().Msgf("couldn't get data tll: %w", err)
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	return jsondata, nil
}

func (dco *DataConfigOperator) Import(ctx context.Context, config []byte) error {
	var configs map[string]int
	if err := json.Unmarshal(config, &configs); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	for key, value := range configs {
		if key == "waterline" {
			if !checkWaterline(value) {
				return ErrInvalidWaterline
			}

			err := dco.dataService.SetDataWaterline(ctx, value)
			if err != nil {
				return fmt.Errorf("couldn't set waterline: %w", err)
			}
		} else {
			// check
			ttlValid, err := checkTTL(ctx, key, value)
			if err != nil {
				return err
			}
			if !ttlValid {
				return ErrInvalidTTL
			}
			//
			err = dco.dataService.SetDataTTL(ctx, key, value)
			if err != nil {
				return fmt.Errorf("couldn't set data tll: %w", err)
			}
		}
	}
	return nil
}

func checkTTL(ctx context.Context, dataType string, ttl int) (bool, error) {
	if ttl <= 0 {
		return false, nil
	}

	dataService, ok := data.GetService(ctx)
	if !ok {
		return false, ErrServiceNotReady
	}
	if dataType == model.DataTypeCold {
		hotLogicTTL, err := dataService.GetDataTTL(ctx, model.DataTypeHotLogic)
		if err != nil {
			return false, err
		}
		if hotLogicTTL >= ttl {
			return false, nil
		}
		hotOfflineTTL, err := dataService.GetDataTTL(ctx, model.DataTypeHotOffline)
		if err != nil {
			return false, err
		}

		return hotOfflineTTL < ttl, nil
	}
	coldTTL, err := dataService.GetDataTTL(ctx, model.DataTypeCold)
	if err != nil {
		return false, err
	}
	return coldTTL > ttl, nil
}

func checkWaterline(percentage int) bool {
	return percentage >= 1 && percentage <= 100
}

package main

import (
	"context"
	"time"

	"github.com/avast/retry-go"
	"github.com/urfave/cli/v2"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	ClearWafCountCmd = &cli.Command{
		Name:   "waf-count-clear",
		Usage:  "cout waf count",
		Action: ClearWafCount,
	}
)

func ClearWafCount(*cli.Context) error {
	mysqlClient, err := NewMysqlClientFromEnv()
	if err != nil {
		logging.GetLogger().Error().Msgf("new mysql client fail:%s", err.Error())
		return err
	}
	return retry.Do(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		return mysqlClient.Get().WithContext(ctx).Exec("UPDATE ivan_waf_services SET attack_number = ?", 0).Error
	}, retry.Attempts(3))
}

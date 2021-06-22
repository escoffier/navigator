package cleaner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type PostgresCleaner struct {
	db     *rdbtools.GormWrapper
	tables []*conf.DumpItem
}

func NewPostgresCleaner(db *rdbtools.GormWrapper, tables []*conf.DumpItem) *PostgresCleaner {
	return &PostgresCleaner{
		db:     db,
		tables: tables,
	}
}

func (c *PostgresCleaner) Clean(ctx context.Context, daysOffset int) error {
	timeFilter := time.Now().Add(-time.Hour * 24 * time.Duration(daysOffset))
	for _, table := range c.tables {
		if err := c.dumpTable(ctx, table, timeFilter); err != nil {
			logging.GetLogger().Error().Msgf("dumpTable %s:%s, err:%s", table.Name, table.TimeField, err.Error())
			return err
		}
	}

	return nil
}

const (
	pgInterval = time.Millisecond * 200
)

func (c *PostgresCleaner) dumpTable(ctx context.Context, table *conf.DumpItem, timeFilter time.Time) error {
	targetPath, tmpPath, err := initDumpInfo(table, timeFilter)
	if err != nil {
		return err
	}

	fileExist, err := checkFileExists(targetPath)
	if err != nil {
		return err
	}

	if fileExist {
		logging.GetLogger().Warn().Msgf("dump file:%s already exists", targetPath)
		return nil
	}

	var targetFile *os.File
	defer func() {
		clearDumpInfo(targetFile, tmpPath)
	}()

	for {
		hasData, err := psqlCopy(ctx, table, timeFilter, tmpPath)
		if err != nil {
			return err
		}

		if !hasData {
			return nil
		}

		if targetFile == nil {
			targetFile, err = os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
		}

		err = mergeDumpFile(tmpPath, targetFile)
		if err != nil {
			return err
		}

		err = clearPGData(ctx, c.db, table, timeFilter)
		if err != nil {
			return err
		}

		time.Sleep(pgInterval)
	}
}

func psqlCopy(ctx context.Context, table *conf.DumpItem, timeFilter time.Time, tmpPath string) (hasData bool, err error) {
	cmd := exec.CommandContext(ctx, "psql",
		"-h", env.GetEnvWithDefault(env.PostgresHost, env.DefaultPostgresHost),
		"-U", env.GetEnvWithDefault(env.PostgresUser, env.DefaultPostgresUser),
		"-d", env.GetEnvWithDefault(env.PostgresDBName, env.DefaultPostgresDBName),
		"-c", fmt.Sprintf("\\copy (select * from %s where %s < '%s' order by %s asc, id asc limit %d) TO '%s'",
			table.Name, table.TimeField, timeFilter.Format("2006-01-02 15:04:05.000"), table.TimeField, table.Batch, tmpPath),
	)

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("PGPASSWORD=%s", env.GetEnvWithDefault(env.PostgresPassword, "")))

	logging.GetLogger().Info().Msgf("execute psql cmd:%s", cmd.String())
	stdout, stderr, err := util.ExecuteCmd(cmd)
	if err != nil {
		return false, fmt.Errorf("execute command fail, err:%s, stderr:%s", err.Error(), stderr)
	}

	if stderr != "" {
		logging.GetLogger().Error().Msgf("execute psql copy fail, stderr:%s", stderr)
		return false, fmt.Errorf("execute %s fail, err:%s", cmd.String(), stderr)
	}

	logging.GetLogger().Info().Msgf("execute psql copy success, stdout:%s", stdout)
	return stdout != "COPY 0\n", nil
}

func clearPGData(ctx context.Context, db *rdbtools.GormWrapper, table *conf.DumpItem, timeFilter time.Time) error {
	sql := fmt.Sprintf("with temp as (select id from %s where %s < ? order by %s asc, id asc limit ?) "+
		"delete from %s where id in (select * from temp)",
		table.Name, table.TimeField, table.TimeField, table.Name)

	clearFunc := func() error {
		return db.Get().WithContext(ctx).Exec(sql, util.GetMillisecondTime(timeFilter), table.Batch).Error
	}

	return util.WithRetry(clearFunc, util.DefaultRetryConf)
}

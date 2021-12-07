package cleaner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type PostgresCleaner struct {
	db     *rdbtools.GormWrapper
	tables []*conf.PGDumpItem
}

func NewPostgresCleaner(db *rdbtools.GormWrapper, tables []*conf.PGDumpItem) *PostgresCleaner {
	return &PostgresCleaner{
		db:     db,
		tables: tables,
	}
}

func (c *PostgresCleaner) Clean(ctx context.Context, arg *def.CleanArg) error {
	defaultTimeFilter := time.Now().Add(-time.Hour * 24 * time.Duration(arg.DaysOffset))
	var errMap = make(map[string]error)
	for _, table := range c.tables {
		filter := defaultTimeFilter
		if arg.Cron && table.TTL > 0 {
			filter = time.Now().Add(-time.Hour * 24 * time.Duration(table.TTL))
		}
		if err := c.dumpTable(ctx, table, filter); err != nil {
			logging.GetLogger().Error().Msgf("dumpTable %s:%s, condition:%s, err:%s",
				table.Name, table.TimeField, table.Condition, err.Error())
			errMap[table.Name] = err
			continue
		}
	}

	if len(errMap) == 0 {
		return nil
	}

	return makeError("pg cleaner error", errMap)
}

const (
	pgInterval = time.Millisecond * 200
)

func (c *PostgresCleaner) dumpTable(ctx context.Context, table *conf.PGDumpItem, timeFilter time.Time) error {
	targetPath, tmpPath, err := initDumpInfo(&table.DumpItem, timeFilter)
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

		time.Sleep(pgInterval)
	}
}

func psqlCopy(ctx context.Context, table *conf.PGDumpItem, timeFilter time.Time, tmpPath string) (hasData bool, err error) {
	cmd := exec.CommandContext(ctx, "psql",
		"-h", util.GetEnvWithDefault(env.RDBHost, env.DefaultRDBHost),
		"-U", util.GetEnvWithDefault(env.RDBUser, env.DefaultRDBUser),
		"-d", util.GetEnvWithDefault(env.RDBDBName, env.DefaultRDBDBName),
		"-c", fmt.Sprintf("\\copy (delete from %s where %s in (select %s from %s where %s < '%s' %s order by %s asc limit %d) returning *) TO '%s'",
			table.Name, getPrimaryKeyGroup(table), getPrimaryKeyColumns(table), table.Name, table.TimeField, timeFilter.Format("2006-01-02 15:04:05.000"), getClearCondition(table), table.TimeField, table.Batch, tmpPath),
	)

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("PGPASSWORD=%s", util.GetEnvWithDefault(env.RDBPassword, "")))

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

func getClearCondition(table *conf.PGDumpItem) string {
	if table.Condition == "" {
		return ""
	}

	return fmt.Sprintf(" and (%s)", table.Condition)
}

func getPrimaryKeyGroup(table *conf.PGDumpItem) string {
	if len(table.PrimaryKey) == 0 {
		return "id"
	}
	if len(table.PrimaryKey) == 1 {
		return table.PrimaryKey[0]
	}

	return fmt.Sprintf("(%s)", strings.Join(table.PrimaryKey, ","))
}

func getPrimaryKeyColumns(table *conf.PGDumpItem) string {
	if len(table.PrimaryKey) == 0 {
		return "id"
	}
	if len(table.PrimaryKey) == 1 {
		return table.PrimaryKey[0]
	}

	return strings.Join(table.PrimaryKey, ",")
}

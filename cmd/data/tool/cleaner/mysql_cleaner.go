package cleaner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
)

type MysqlCleaner struct {
	db     *databases.RDBInstance
	tables []*conf.RDBDumpItem
}

func NewMysqlCleaner(db *databases.RDBInstance, tables []*conf.RDBDumpItem) *MysqlCleaner {
	return &MysqlCleaner{
		db:     db,
		tables: tables,
	}
}

func (c *MysqlCleaner) Clean(ctx context.Context, arg *def.CleanArg) error {
	defaultTimeFilter := time.Now().Add(-time.Hour * 24 * time.Duration(arg.DaysOffset))
	var errMap = make(map[string]error)
	for _, table := range c.tables {
		filter := defaultTimeFilter
		if arg.Cron && table.TTL > 0 {
			filter = time.Now().Add(-time.Hour * 24 * time.Duration(table.TTL))
		}
		if err := c.dumpTable(ctx, c.db, table, filter); err != nil {
			logging.GetLogger().Error().Msgf("dumpTable %s:%s, condition:%s, err:%s",
				table.Name, table.TimeField, table.Condition, err.Error())
			errMap[table.Name] = err
			continue
		}
	}

	if len(errMap) == 0 {
		return nil
	}

	return makeError("mysql cleaner error", errMap)
}

const (
	mysqlInterval = time.Millisecond * 200
)

func (c *MysqlCleaner) dumpTable(ctx context.Context, db *databases.RDBInstance, table *conf.RDBDumpItem, timeFilter time.Time) error {
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
		hasData, err := mysqlDump(ctx, db, table, timeFilter, tmpPath)
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

		time.Sleep(mysqlInterval)
	}
}

func mysqlDump(ctx context.Context, db *databases.RDBInstance, table *conf.RDBDumpItem, timeFilter time.Time, tmpPath string) (hasData bool, err error) {
	sort := getPrimaryKeySortColumns(table, "desc")
	clearCondition := fmt.Sprintf("('%s' < '%s' %s)",
		table.TimeField, timeFilter.Format("2006-01-02 15:04:05.000"), getClearCondition(table))
	cmd := exec.CommandContext(ctx, "mysqldump", "-t",
		"-u", util.GetEnvWithDefault(env.RDBUser, ""),
		fmt.Sprintf("-p%s", util.GetEnvWithDefault(env.RDBPassword, "")),
		util.GetEnvWithDefault(env.RDBDBName, ""),
		table.Name,
		"-h", util.GetEnvWithDefault(env.RDBHost, ""),
		"-P", util.GetEnvWithDefault(env.RDBPort, ""),
		fmt.Sprintf("--where=\"%s order by (%s) desc limit %d\"", clearCondition, sort, table.Batch),
	)

	outfile, err := os.Create(tmpPath)
	if err != nil {
		return false, err
	}
	defer outfile.Close()
	cmd.Stdout = outfile

	logging.GetLogger().Info().Msgf("execute mysqldump cmd:%s", cmd.String())
	_, stderr, err := util.ExecuteCmd(cmd)
	if err != nil {
		return false, fmt.Errorf("execute command fail, err:%s, stderr:%s", err.Error(), stderr)
	}

	if stderr != "" {
		logging.GetLogger().Error().Msgf("execute mysqldump, stderr:%s", stderr)
		return false, fmt.Errorf("execute %s fail, err:%s", cmd.String(), stderr)
	}

	del := func() error {
		dbInstance := db.Get().Exec(fmt.Sprintf("delete from %s where %s order by %s limit %d",
			table.Name, clearCondition, sort, table.Batch))
		if dbInstance.Error != nil {
			return dbInstance.Error
		}
		hasData = dbInstance.RowsAffected > 0
		return nil
	}
	if err = util.RetryWithBackoff(ctx, del); err != nil {
		return false, err
	}

	return hasData, nil
}

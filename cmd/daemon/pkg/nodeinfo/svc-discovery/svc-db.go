package svcdiscovery

import (
	"context"
	"fmt"
	"github.com/dlclark/regexp2"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
	"path/filepath"
	"strings"
	"time"
)

// Mysql
var regexSvcMysql = `^[^\s]*mysqld\s`
var regexSvcMysqlVersion = `(?<=Ver\s)[^\s]+`
var regexSvcMysqlRootDir = `(?<=--basedir=)[^\s]+`
var regexSvcMysqlConfigDir = `(?<=--defaults-file=)[^\s]+`
var regexSvcMysqlDataDir = `(?<=--datadir=)[^\s]+`
var regexSvcMysqlLogDir = `(?<=--log-error=)[^\s]+`
var regexSvcMysqlPort = `(?<=port\s*=\s).*`
var regexSvcMysqlDataDirInConf = `(?<=datadir\s*=\s).*`

type MysqlSvc struct {
	SvcRegex           *regexp2.Regexp
	SvcVersionRegex    *regexp2.Regexp
	RootDirRegex       *regexp2.Regexp
	ConfigDirRegex     *regexp2.Regexp
	DataDirRegex       *regexp2.Regexp
	LogDirRegex        *regexp2.Regexp
	PortRegex          *regexp2.Regexp
	DataDirInConfRegex *regexp2.Regexp
	Name               string // 服务类型
	Port               string
	RootDir            string // 主目录路径
	DataDir            string
	ConfigDir          string
	LogDir             string
}

func NewMysqlSvc() ISvcDiscovery {
	var mysql MysqlSvc
	mysql.Name = assets.BusiSvcMysql
	mysql.Port = "3306"
	mysql.RootDir = "/usr/sbin/"
	mysql.DataDir = "/var/lib/mysql/"
	mysql.ConfigDir = "/etc/mysql/my.cnf"
	mysql.LogDir = "/var/log/mysql/"

	var err error
	mysql.SvcRegex, err = regexp2.Compile(regexSvcMysql, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysql)
		return nil
	}
	mysql.SvcVersionRegex, err = regexp2.Compile(regexSvcMysqlVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysqlVersion)
		return nil
	}
	mysql.RootDirRegex, err = regexp2.Compile(regexSvcMysqlRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysqlRootDir)
		return nil
	}
	mysql.ConfigDirRegex, err = regexp2.Compile(regexSvcMysqlConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysqlConfigDir)
		return nil
	}
	mysql.DataDirRegex, err = regexp2.Compile(regexSvcMysqlDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysqlDataDir)
		return nil
	}
	mysql.LogDirRegex, err = regexp2.Compile(regexSvcMysqlLogDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysqlLogDir)
		return nil
	}
	mysql.PortRegex, err = regexp2.Compile(regexSvcMysqlPort, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysqlPort)
		return nil
	}
	mysql.DataDirInConfRegex, err = regexp2.Compile(regexSvcMysqlDataDirInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMysqlDataDirInConf)
		return nil
	}
	return &mysql
}
func (t *MysqlSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	var binaryPath string
	for _, cmd := range cmdList {
		cmdStr := cmd.cmdStr
		isMatch, err := t.SvcRegex.MatchString(cmdStr)
		if err != nil || isMatch == false {
			continue
		}
		if svcInfo.RootDir == "" {
			match, err := t.RootDirRegex.FindStringMatch(cmdStr)
			if err == nil && match != nil {
				svcInfo.RootDir = match.String()
			}
		}

		if svcInfo.DataDir == "" {
			match, err := t.DataDirRegex.FindStringMatch(cmdStr)
			if err == nil && match != nil {
				svcInfo.DataDir = match.String()
			}
		}

		if svcInfo.ConfigDir == "" {
			match, err := t.ConfigDirRegex.FindStringMatch(cmdStr)
			if err == nil && match != nil {
				svcInfo.ConfigDir = match.String()
			}
		}

		if svcInfo.LogDir == "" {
			match, err := t.LogDirRegex.FindStringMatch(cmdStr)
			if err == nil && match != nil {
				svcInfo.LogDir = match.String()
			}
		}
		svcInfo.Name = t.Name
		svcInfo.Port = t.Port
		svcInfo.Cmd = cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		index := strings.Index(cmdStr, " ")
		if index != -1 {
			binaryPath = cmdStr[:index]
		} else {
			binaryPath = cmdStr
		}
		break
	}
	if svcInfo.Name == "" {
		return nil
	}
	if svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
	}
	if svcInfo.ConfigDir == "" {
		svcInfo.ConfigDir = t.ConfigDir
	}
	if svcInfo.LogDir == "" {
		svcInfo.LogDir = t.LogDir
	}
	// port
	portCmd := []string{"/bin/bash", "-c", `grep -E "port|datadir" ` + svcInfo.ConfigDir}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	output, err := runCmd(ctx, containerId, portCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", portCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", portCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Port = match.String()
		}
		if svcInfo.DataDir == "" {
			match, err = t.DataDirInConfRegex.FindStringMatch(output)
			if err == nil && match != nil {
				svcInfo.DataDir = match.String()
			}
		}
	}
	if svcInfo.DataDir == "" {
		svcInfo.DataDir = t.DataDir
	}
	// version
	/*
		root@dbapps-7f7bbc9456-kszzz:/# mysqld -V
		/usr/sbin/mysqld  Ver 8.0.27 for Linux on x86_64 (MySQL Community Server - GPL)
	*/
	versionCmd := []string{binaryPath, "-V"}
	ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
	output, err = runCmd(ctx, containerId, versionCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// PostgreSql
var regexSvcPostgreSQL = `^[^\s]*postgres\s`
var regexSvcPostgreSQLVersion = `(?<=PostgreSQL\)\s)[^\s]+`
var regexSvcPostgreSQLConfigDir = `(?<=config_file)[^\s]+`
var regexSvcPostgreSQLDataDir = `(?<=-D\s)[^\s]+`
var regexSvcPostgreSQLLogDir = `(?<=log_file)[^\s]+`
var regexSvcPostgreSQLPort = `(?<=port\s*=\s).*`
var regexSvcPostgreSQLDataDirInCnf = `(?<=data_directory\s*=\s).*?(?=\s)`

type PostgreSQLSvc struct {
	SvcRegex           *regexp2.Regexp
	SvcVersionRegex    *regexp2.Regexp
	ConfigDirRegex     *regexp2.Regexp
	DataDirRegex       *regexp2.Regexp
	LogDirRegex        *regexp2.Regexp
	PortRegex          *regexp2.Regexp
	DataDirInConfRegex *regexp2.Regexp
	Name               string // 服务类型
	Port               string
	RootDir            string // 主目录路径
	DataDir            string
	ConfigDir          string
	LogDir             string
}

func NewPostgreSQLSvc() ISvcDiscovery {
	var pgsql PostgreSQLSvc
	pgsql.Name = assets.BusiSvcPostgreSQL
	pgsql.Port = "5432"
	pgsql.DataDir = "/var/lib/postgresql/data"
	pgsql.ConfigDir = "/var/lib/postgresql/data/postgresql.conf"
	pgsql.LogDir = filepath.Join(pgsql.DataDir)

	var err error
	pgsql.SvcRegex, err = regexp2.Compile(regexSvcPostgreSQL, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQL)
		return nil
	}
	pgsql.SvcVersionRegex, err = regexp2.Compile(regexSvcPostgreSQLVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLVersion)
		return nil
	}
	pgsql.ConfigDirRegex, err = regexp2.Compile(regexSvcPostgreSQLConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLConfigDir)
		return nil
	}
	pgsql.DataDirRegex, err = regexp2.Compile(regexSvcPostgreSQLDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLDataDir)
		return nil
	}
	pgsql.LogDirRegex, err = regexp2.Compile(regexSvcPostgreSQLLogDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLLogDir)
		return nil
	}
	pgsql.PortRegex, err = regexp2.Compile(regexSvcPostgreSQLPort, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLPort)
		return nil
	}
	pgsql.DataDirInConfRegex, err = regexp2.Compile(regexSvcPostgreSQLDataDirInCnf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLDataDirInCnf)
		return nil
	}
	return &pgsql
}
func (t *PostgreSQLSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	var binaryPath string
	for _, cmd := range cmdList {
		cmdStr := cmd.cmdStr
		isMatch, err := t.SvcRegex.MatchString(cmdStr)
		if err != nil || isMatch == false {
			continue
		}
		match, err := t.DataDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.DataDir = match.String()
		}
		match, err = t.ConfigDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.ConfigDir = match.String()
		}
		match, err = t.LogDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.LogDir = match.String()
		}
		svcInfo.Name = t.Name
		//svcInfo.Port = t.Port
		svcInfo.Cmd = cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		index := strings.Index(cmdStr, " ")
		if index != -1 {
			binaryPath = cmdStr[:index]
		} else {
			binaryPath = cmdStr
		}
		break
	}
	if svcInfo.Name == "" {
		return nil
	}

	isFullPath := strings.Contains(binaryPath, "/")
	if isFullPath {
		svcInfo.RootDir = strings.TrimSuffix(binaryPath, "bin/postgres")
	}

	if svcInfo.ConfigDir == "" {
		svcInfo.ConfigDir = t.ConfigDir
	}
	if svcInfo.LogDir == "" {
		svcInfo.LogDir = t.LogDir
	}
	// port
	configFileCmd := []string{"/bin/bash", "-c", `grep -E "^port|^data_directory" ` + svcInfo.ConfigDir}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	output, err := runCmd(ctx, containerId, configFileCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", configFileCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", configFileCmd, output)
		match, err := t.PortRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Port = match.String()
		}
		if svcInfo.DataDir == "" {
			match, err = t.DataDirInConfRegex.FindStringMatch(output)
			if err == nil && match != nil {
				svcInfo.DataDir = match.String()
			}
		}
	}
	if svcInfo.DataDir == "" {
		svcInfo.DataDir = t.DataDir
	}
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}
	// version
	/*
		root@dbapps-7f7bbc9456-vbw4d:/usr/lib/postgresql/13/bin# postgres -V
		postgres (PostgreSQL) 13.5 (Debian 13.5-1.pgdg110+1)
	*/
	versionCmd := []string{binaryPath, "-V"}
	ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
	output, err = runCmd(ctx, containerId, versionCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// MogoDB
var regexSvcMogoDb = `^[^\s]*mongod\s`
var regexSvcMogoDbVersion = `(?<=version\s).*`
var regexSvcMogoDbConfigDir = `(?<=--config\s)[^\s]+`
var regexSvcMogoDbDataDir = `(?<=--dbpath\s)[^\s]+`
var regexSvcMogoDbLogDir = `(?<=--logpath\s)[^\s]+`
var regexSvcMogoDbPortInConf = `(?<=port:\s).*?(?=\s)`
var regexSvcMogoDbDataDirInConf = `(?<=dbPath:\s).*?(?=\s)`
var regexSvcMogoDbLogDirInConf = `(?<=  path:\s).*?(?=\s)`

type MogoDbSvc struct {
	SvcRegex           *regexp2.Regexp
	SvcVersionRegex    *regexp2.Regexp
	ConfigDirRegex     *regexp2.Regexp
	DataDirRegex       *regexp2.Regexp
	LogDirRegex        *regexp2.Regexp
	PortInConfRegex    *regexp2.Regexp
	DataDirInConfRegex *regexp2.Regexp
	LogDirInConfRegex  *regexp2.Regexp
	Name               string // 服务类型
	Port               string
	RootDir            string // 主目录路径
	DataDir            string
	ConfigDir          string
	LogDir             string
}

func NewMogoDbSvc() ISvcDiscovery {
	var mogodb MogoDbSvc
	mogodb.Name = assets.BusiSvcMogoDB
	mogodb.Port = "27017"
	mogodb.ConfigDir = "/etc/mongod.conf.orig"
	mogodb.DataDir = "/var/lib/mongodb"
	mogodb.LogDir = "/var/log/mongodb"
	var err error
	mogodb.SvcRegex, err = regexp2.Compile(regexSvcMogoDb, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDb)
		return nil
	}
	mogodb.SvcVersionRegex, err = regexp2.Compile(regexSvcMogoDbVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDbVersion)
		return nil
	}
	mogodb.ConfigDirRegex, err = regexp2.Compile(regexSvcMogoDbConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDbConfigDir)
		return nil
	}
	mogodb.DataDirRegex, err = regexp2.Compile(regexSvcMogoDbDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDbDataDir)
		return nil
	}
	mogodb.LogDirRegex, err = regexp2.Compile(regexSvcMogoDbLogDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDbLogDir)
		return nil
	}
	mogodb.PortInConfRegex, err = regexp2.Compile(regexSvcMogoDbPortInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDbPortInConf)
		return nil
	}
	mogodb.DataDirInConfRegex, err = regexp2.Compile(regexSvcMogoDbDataDirInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDbDataDirInConf)
		return nil
	}
	mogodb.LogDirInConfRegex, err = regexp2.Compile(regexSvcMogoDbLogDirInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcMogoDbLogDirInConf)
		return nil
	}
	return &mogodb
}
func (t *MogoDbSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	var binaryPath string
	for _, cmd := range cmdList {
		cmdStr := cmd.cmdStr
		isMatch, err := t.SvcRegex.MatchString(cmdStr)
		if err != nil || isMatch == false {
			continue
		}
		match, err := t.DataDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.DataDir = match.String()
		}
		match, err = t.ConfigDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.ConfigDir = match.String()
		}
		match, err = t.LogDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.LogDir = match.String()
		}
		svcInfo.Name = t.Name
		//svcInfo.Port = t.Port
		svcInfo.Cmd = cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		svcInfo.RootDir = svcInfo.BinaryDir
		splitN := strings.SplitN(cmdStr, " ", 1)
		if len(splitN) > 0 {
			binaryPath = splitN[0]
		}
		break
	}
	if svcInfo.Name == "" {
		return nil
	}

	if svcInfo.ConfigDir == "" {
		svcInfo.ConfigDir = t.ConfigDir
	}

	// parse config file
	configFileCmd := []string{"/bin/sh", "-c", fmt.Sprintf(`grep -E "dbPath|path|port" %s`, svcInfo.ConfigDir)}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	output, err := runCmd(ctx, containerId, configFileCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", configFileCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", configFileCmd, output)
		match, err := t.PortInConfRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Port = match.String()
		}
		if svcInfo.DataDir == "" {
			match, err = t.DataDirInConfRegex.FindStringMatch(output)
			if err == nil && match != nil {
				svcInfo.DataDir = match.String()
			}
		}
		if svcInfo.LogDir == "" {
			match, err = t.LogDirInConfRegex.FindStringMatch(output)
			if err == nil && match != nil {
				svcInfo.LogDir = match.String()
			}
		}
	}

	if svcInfo.DataDir == "" {
		svcInfo.DataDir = t.DataDir
	}

	if svcInfo.LogDir == "" {
		svcInfo.LogDir = t.LogDir
	}
	// version
	/*
		root@dbapps-7f7bbc9456-vbw4d:/# mongod --version|grep "db "
		db version v5.0.5
	*/
	versionCmd := []string{"/bin/sh", "-c", binaryPath + ` --version|grep "db "`}
	ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
	output, err = runCmd(ctx, containerId, versionCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// Redis
var regexSvcRedis = `^[^\s]*redis-server\s`
var regexSvcRedisVersion = `(?<=v=)[^\s]+`
var regexSvcRedisPort = `(?<=--port\s)[^\s]+`
var regexSvcRedisConfigDir = `([^\s]*\.conf)` // 获取 conf 配置文件路径
var regexSvcRedisDataDir = `(?<=--dir\s)[^\s]+`
var regexSvcRedisLogDir = `(?<=--logfile\s)[^\s]+`
var regexSvcRedisDataDirInConf = `(?<=dir\s)[^\s]+`
var regexSvcRedisLogDirInConf = `(?<=logfile\s)[^\s]+`
var regexSvcRedisPortInConf = `(?<=port\s)[^\s]+`

type RedisSvc struct {
	SvcRegex           *regexp2.Regexp
	SvcVersionRegex    *regexp2.Regexp
	SvcPortRegex       *regexp2.Regexp
	ConfigDirRegex     *regexp2.Regexp
	DataDirRegex       *regexp2.Regexp
	LogDirRegex        *regexp2.Regexp
	DataDirInConfRegex *regexp2.Regexp
	LogDirInConfRegex  *regexp2.Regexp
	PortInConfRegex    *regexp2.Regexp
	Name               string // 服务类型
	Port               string
	RootDir            string // 主目录路径
	DataDir            string
	ConfigDir          string
	LogDir             string
}

func NewRedisSvc() ISvcDiscovery {
	var redis RedisSvc
	redis.Name = assets.BusiSvcRedis
	redis.Port = "6379"

	var err error
	redis.SvcRegex, err = regexp2.Compile(regexSvcRedis, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedis)
		return nil
	}
	redis.SvcVersionRegex, err = regexp2.Compile(regexSvcRedisVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisVersion)
		return nil
	}
	redis.SvcPortRegex, err = regexp2.Compile(regexSvcRedisPort, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisPort)
		return nil
	}
	redis.ConfigDirRegex, err = regexp2.Compile(regexSvcRedisConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisConfigDir)
		return nil
	}
	redis.DataDirRegex, err = regexp2.Compile(regexSvcRedisDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisDataDir)
		return nil
	}
	redis.LogDirRegex, err = regexp2.Compile(regexSvcRedisLogDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisLogDir)
		return nil
	}
	redis.DataDirInConfRegex, err = regexp2.Compile(regexSvcRedisDataDirInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisDataDirInConf)
		return nil
	}
	redis.LogDirInConfRegex, err = regexp2.Compile(regexSvcRedisLogDirInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisLogDirInConf)
		return nil
	}
	redis.PortInConfRegex, err = regexp2.Compile(regexSvcRedisPortInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRedisPortInConf)
		return nil
	}
	return &redis
}
func (t *RedisSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		cmdStr := cmd.cmdStr
		isMatch, err := t.SvcRegex.MatchString(cmdStr)
		if err != nil || isMatch == false {
			continue
		}
		match, err := t.SvcPortRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.Port = match.String()
		}
		match, err = t.DataDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.DataDir = match.String()
		}
		match, err = t.ConfigDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.ConfigDir = match.String()
		}
		match, err = t.LogDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.LogDir = match.String()
		}
		svcInfo.Name = t.Name
		svcInfo.Cmd = cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		svcInfo.RootDir = svcInfo.BinaryDir
		break
	}
	if svcInfo.Name == "" {
		return nil
	}

	if svcInfo.ConfigDir != "" {
		configCmd := []string{"/bin/bash", "-c", `grep  -E "^dir|^logfile|^port"`}
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := runCmd(ctx, containerId, configCmd)
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", configCmd)
		} else {
			logging.Get().Info().Msgf("run cmd[%s] result:%s", configCmd, output)
			if svcInfo.DataDir == "" {
				match, err := t.DataDirInConfRegex.FindStringMatch(output)
				if err == nil && match != nil {
					dataDir := match.String()
					if filepath.IsAbs(dataDir) {
						svcInfo.DataDir = dataDir
					} else {
						svcInfo.DataDir = filepath.Join(cwd, dataDir)
					}
				}
			}

			if svcInfo.LogDir == "" {
				match, err := t.LogDirInConfRegex.FindStringMatch(output)
				if err == nil && match != nil {
					dir := match.String()
					if filepath.IsAbs(dir) {
						svcInfo.LogDir = dir
					} else {
						svcInfo.LogDir = filepath.Join(cwd, dir)
					}
				}
			}
			if svcInfo.Port == "" {
				match, err := t.PortInConfRegex.FindStringMatch(output)
				if err == nil && match != nil {
					svcInfo.Port = match.String()
				}
			}

		}
	}

	if svcInfo.DataDir == "" {
		svcInfo.DataDir = cwd
	}
	if svcInfo.LogDir == "" {
		svcInfo.LogDir = t.LogDir
	}
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}

	// version
	/*
		root@51c1c6-test444-66f64568fc-jq2f6:/usr/local/bin# redis-server -v
		Redis server v=6.2.4 sha=00000000:0 malloc=jemalloc-5.1.0 bits=64 build=d8a9b614fc8bcf79
	*/
	versionCmd := []string{svcInfo.BinaryDir, "-v"}
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	output, err := runCmd(ctx, containerId, versionCmd)

	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// Grafana
var regexSvcGrafana = `^[^\s]*grafana-server\s`
var regexSvcGrafanaVersion = `(?<=version\s).*`
var regexSvcGrafanaRootDir = `(?<=-homepath\s)[^\s]+`
var regexSvcGrafanaConfigDir = `(?<=-config\s)[^\s]+`
var regexSvcGrafanaDataDir = `(?<=-storage\s)[^\s]+`
var regexSvcGrafanaLogDir = `(?<=-logpath\s)[^\s]+`
var regexSvcGrafanaPortInConf = `(?<=http_port\s=\s+).*`
var regexSvcGrafanaDataDirInConf = `(?<=[!;]path\s*=\s).*`
var regexSvcGrafanaLogDirInConf = `(?<=logs\s=\s+).*`

type GrafanaSvc struct {
	SvcRegex           *regexp2.Regexp
	SvcVersionRegex    *regexp2.Regexp
	SvcRootRegex       *regexp2.Regexp
	ConfigDirRegex     *regexp2.Regexp
	DataDirRegex       *regexp2.Regexp
	LogDirRegex        *regexp2.Regexp
	PortInConfRegex    *regexp2.Regexp
	DataDirInConfRegex *regexp2.Regexp
	LogDirInConfRegex  *regexp2.Regexp
	Name               string // 服务类型
	Port               string
	RootDir            string // 主目录路径
	DataDir            string
	ConfigDir          string
	LogDir             string
}

func NewGrafanaSvc() ISvcDiscovery {
	var grafana GrafanaSvc
	grafana.Name = assets.BusiSvcGrafana
	grafana.Port = "3000"
	grafana.RootDir = "/usr/share/grafana/"
	grafana.LogDir = "/var/log/grafana/"
	grafana.ConfigDir = "/etc/grafana/grafana.ini"

	var err error
	grafana.SvcRegex, err = regexp2.Compile(regexSvcGrafana, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafana)
		return nil
	}
	grafana.SvcVersionRegex, err = regexp2.Compile(regexSvcGrafanaVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaVersion)
		return nil
	}
	grafana.SvcRootRegex, err = regexp2.Compile(regexSvcGrafanaRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaRootDir)
		return nil
	}
	grafana.ConfigDirRegex, err = regexp2.Compile(regexSvcGrafanaConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaConfigDir)
		return nil
	}
	grafana.DataDirRegex, err = regexp2.Compile(regexSvcGrafanaDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaDataDir)
		return nil
	}
	grafana.LogDirRegex, err = regexp2.Compile(regexSvcGrafanaLogDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaLogDir)
		return nil
	}
	grafana.PortInConfRegex, err = regexp2.Compile(regexSvcGrafanaPortInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaPortInConf)
		return nil
	}
	grafana.DataDirInConfRegex, err = regexp2.Compile(regexSvcGrafanaDataDirInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaDataDirInConf)
		return nil
	}
	grafana.LogDirInConfRegex, err = regexp2.Compile(regexSvcGrafanaLogDirInConf, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcGrafanaLogDirInConf)
		return nil
	}

	return &grafana
}
func (t *GrafanaSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		cmdStr := cmd.cmdStr
		isMatch, err := t.SvcRegex.MatchString(cmdStr)
		if err != nil || isMatch == false {
			continue
		}
		match, err := t.SvcRootRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.Port = match.String()
		}
		match, err = t.DataDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.DataDir = match.String()
		}
		match, err = t.ConfigDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.ConfigDir = match.String()
		}
		match, err = t.LogDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.LogDir = match.String()
		}
		svcInfo.Name = t.Name
		svcInfo.Cmd = cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		break
	}
	if svcInfo.Name == "" {
		return nil
	}
	if svcInfo.RootDir == "" {
		if cwd != "/" {
			svcInfo.RootDir = cwd
		} else {
			svcInfo.RootDir = t.RootDir
		}
	}

	if svcInfo.ConfigDir == "" {
		svcInfo.ConfigDir = t.ConfigDir
	} else {
		configCmd := []string{"/bin/bash", "-c", `grep -E -C1 "path relative to data_path setting|^logs|^http_port" ` + svcInfo.ConfigDir}
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := runCmd(ctx, containerId, configCmd)
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", configCmd)
		} else {
			logging.Get().Info().Msgf("run cmd[%s] result:%s", configCmd, output)
			if svcInfo.Port != "" {
				match, err := t.PortInConfRegex.FindStringMatch(output)
				if err == nil && match != nil {
					svcInfo.Port = match.String()
				}
			}
			if svcInfo.DataDir == "" {
				match, err := t.DataDirInConfRegex.FindStringMatch(output)
				if err == nil && match != nil {
					svcInfo.DataDir = match.String()
				}
			}
			if svcInfo.LogDir == "" {
				match, err := t.LogDirInConfRegex.FindStringMatch(output)
				if err == nil && match != nil {
					svcInfo.LogDir = match.String()
				}
			}
		}
	}

	if svcInfo.DataDir == "" {
		svcInfo.DataDir = t.DataDir
	}
	if svcInfo.LogDir == "" {
		svcInfo.LogDir = t.LogDir
	}
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}

	// version
	/*
		bash-5.0$ grafana-cli -v
		Grafana CLI version 7.3.6
	*/
	versionCmd := []string{"grafana-cli", "-v"}
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	output, err := runCmd(ctx, containerId, versionCmd)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// Rsyslog
var regexSvcRsyslog = `^[^\s]*rsyslogd\s`
var regexSvcRsyslogVersion = `(?<=rsyslogd\s)[^,]+`
var regexSvcRsyslogConfigDir = `(?<=-config\s)[^\s]+`
var regexSvcRsyslogDataDir = `(?<=-f\s?).*?(\s)`

type RsyslogSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	ConfigDirRegex  *regexp2.Regexp
	DataDirRegex    *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	DataDir         string
	ConfigDir       string
	LogDir          string
}

func NewRsyslogSvc() ISvcDiscovery {
	var rsyslog RsyslogSvc
	rsyslog.Name = assets.BusiSvcRsyslog
	rsyslog.ConfigDir = "/etc/rsyslog.conf"

	var err error
	rsyslog.SvcRegex, err = regexp2.Compile(regexSvcRsyslog, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslog)
		return nil
	}
	rsyslog.SvcVersionRegex, err = regexp2.Compile(regexSvcRsyslogVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslogVersion)
		return nil
	}
	rsyslog.ConfigDirRegex, err = regexp2.Compile(regexSvcRsyslogConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslogConfigDir)
		return nil
	}
	rsyslog.DataDirRegex, err = regexp2.Compile(regexSvcRsyslogDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslogDataDir)
		return nil
	}
	return &rsyslog
}
func (t *RsyslogSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	var binaryPath string
	for _, cmd := range cmdList {
		cmdStr := cmd.cmdStr
		isMatch, err := t.SvcRegex.MatchString(cmdStr)
		if err != nil || isMatch == false {
			continue
		}
		match, err := t.DataDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.DataDir = match.String()
		}
		match, err = t.ConfigDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.ConfigDir = strings.TrimSpace(match.String())
		}
		svcInfo.Name = t.Name
		svcInfo.Cmd = cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		splitN := strings.SplitN(cmdStr, " ", 1)
		if len(splitN) > 0 {
			binaryPath = splitN[0]
		}
		break
	}
	if svcInfo.Name == "" {
		return nil
	}
	if svcInfo.DataDir == "" {
		svcInfo.DataDir = t.DataDir
	}
	if svcInfo.ConfigDir == "" {
		svcInfo.ConfigDir = t.ConfigDir
	}
	if svcInfo.LogDir == "" {
		svcInfo.LogDir = t.LogDir
	}

	// version
	/*
		/home/appliance # rsyslogd -v |grep "rsyslogd"
		rsyslogd 8.36.0, compiled with:
	*/
	versionCmd := []string{"/bin/sh", "-c", binaryPath + " -v |grep rsyslogd"}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	output, err := runCmd(ctx, containerId, versionCmd)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

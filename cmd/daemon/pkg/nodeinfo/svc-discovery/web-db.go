package svcdiscovery

import (
	"context"
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

type MysqlSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
	ConfigDirRegex  *regexp2.Regexp
	DataDirRegex    *regexp2.Regexp
	LogDirRegex     *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	DataDir         string
	ConfigDir       string
	LogDir          string
}

func NewMysqlSvc() ISvcDiscovery {
	var mysql MysqlSvc
	mysql.Name = assets.BusiSvcMysql
	mysql.Port = "3306"
	mysql.RootDir = "/usr/sbin/"
	mysql.DataDir = "/var/lib/mysql/"
	mysql.ConfigDir = "/etc/mysql/"
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
		root@dbapps-7f7bbc9456-vbw4d:/# mysql -V
		mysql  Ver 8.0.27 for Linux on x86_64 (MySQL Community Server - GPL)
	*/
	mysqlPath := strings.ReplaceAll(binaryPath, "mysqld", "mysql")
	versionCmd := []string{mysqlPath, "-V"}
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

// PostgreSql
var regexSvcPostgreSQL = `^[^\s]*postgres\s`
var regexSvcPostgreSQLVersion = `(?<=PostgreSQL\)\s)[^\s]+`
var regexSvcPostgreSQLConfigDir = `(?<=config_file)[^\s]+`
var regexSvcPostgreSQLDataDir = `(?<=-D\s)[^\s]+`
var regexSvcPostgreSQLLogDir = `(?<=log_file)[^\s]+`

type PostgreSQLSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	ConfigDirRegex  *regexp2.Regexp
	DataDirRegex    *regexp2.Regexp
	LogDirRegex     *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	DataDir         string
	ConfigDir       string
	LogDir          string
}

func NewPostgreSQLSvc() ISvcDiscovery {
	var mysql PostgreSQLSvc
	mysql.Name = assets.BusiSvcPostgreSQL
	mysql.Port = "5432"
	mysql.DataDir = "/var/lib/postgresql/data"
	mysql.ConfigDir = mysql.DataDir
	mysql.LogDir = filepath.Join(mysql.DataDir)

	var err error
	mysql.SvcRegex, err = regexp2.Compile(regexSvcPostgreSQL, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQL)
		return nil
	}
	mysql.SvcVersionRegex, err = regexp2.Compile(regexSvcPostgreSQLVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLVersion)
		return nil
	}
	mysql.ConfigDirRegex, err = regexp2.Compile(regexSvcPostgreSQLConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLConfigDir)
		return nil
	}
	mysql.DataDirRegex, err = regexp2.Compile(regexSvcPostgreSQLDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLDataDir)
		return nil
	}
	mysql.LogDirRegex, err = regexp2.Compile(regexSvcPostgreSQLLogDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcPostgreSQLLogDir)
		return nil
	}
	return &mysql
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

	isFullPath := strings.Contains(binaryPath, "/")
	if isFullPath {
		svcInfo.RootDir = strings.TrimSuffix(binaryPath, "bin/postgres")
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
		root@dbapps-7f7bbc9456-vbw4d:/usr/lib/postgresql/13/bin# postgres -V
		postgres (PostgreSQL) 13.5 (Debian 13.5-1.pgdg110+1)
	*/
	versionCmd := []string{binaryPath, "-V"}
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

// MogoDB
var regexSvcMogoDb = `^[^\s]*mongod\s`
var regexSvcMogoDbVersion = `(?<=version\s).*`
var regexSvcMogoDbConfigDir = `(?<=--config\s)[^\s]+`
var regexSvcMogoDbDataDir = `(?<=--dbpath\s)[^\s]+`
var regexSvcMogoDbLogDir = `(?<=--logpath\s)[^\s]+`

type MogoDbSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	ConfigDirRegex  *regexp2.Regexp
	DataDirRegex    *regexp2.Regexp
	LogDirRegex     *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	DataDir         string
	ConfigDir       string
	LogDir          string
}

func NewMogoDbSvc() ISvcDiscovery {
	var mogodb MogoDbSvc
	mogodb.Name = assets.BusiSvcMogoDB
	mogodb.Port = "27017"
	mogodb.ConfigDir = "/etc" // /etc/mongod.conf.orig
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
		svcInfo.Port = t.Port
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
		root@dbapps-7f7bbc9456-vbw4d:/# mongod --version|grep "db "
		db version v5.0.5
	*/
	versionCmd := []string{"/bin/sh", "-c", binaryPath + ` --version|grep "db "`}
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

// Redis
var regexSvcRedis = `^[^\s]*redis-server\s`
var regexSvcRedisVersion = `(?<=redis-cli\s).*`
var regexSvcRedisPort = `(?<=--port\s)[^\s]+`
var regexSvcRedisConfigDir = `(?<=--config-file\s)[^\s]+`
var regexSvcRedisDataDir = `(?<=--dir\s)[^\s]+`
var regexSvcRedisLogDir = `(?<=--logfile\s)[^\s]+`

type RedisSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	SvcPortRegex    *regexp2.Regexp
	ConfigDirRegex  *regexp2.Regexp
	DataDirRegex    *regexp2.Regexp
	LogDirRegex     *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	DataDir         string
	ConfigDir       string
	LogDir          string
}

func NewRedisSvc() ISvcDiscovery {
	var redis RedisSvc
	redis.Name = assets.BusiSvcRedis
	redis.Port = "6379"
	redis.DataDir = "/var/lib/redis/"
	redis.LogDir = "/var/log/redis/"

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
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}

	// version
	/*
		root@dbapps-7f7bbc9456-vbw4d:/data# redis-cli -v
		redis-cli 6.2.6
	*/
	versionCmd := []string{"redis-cli", "-v"}
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

// Grafana
var regexSvcGrafana = `^[^\s]*grafana-server\s`
var regexSvcGrafanaVersion = `(?<=version\s).*`
var regexSvcGrafanaRootDir = `(?<=-homepath\s)[^\s]+`
var regexSvcGrafanaConfigDir = `(?<=-config\s)[^\s]+`
var regexSvcGrafanaDataDir = `(?<=-storage\s)[^\s]+`
var regexSvcGrafanaLogDir = `(?<=-logpath\s)[^\s]+`

type GrafanaSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	SvcRootRegex    *regexp2.Regexp
	ConfigDirRegex  *regexp2.Regexp
	DataDirRegex    *regexp2.Regexp
	LogDirRegex     *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	DataDir         string
	ConfigDir       string
	LogDir          string
	BinDir          string
}

func NewGrafanaSvc() ISvcDiscovery {
	var grafana GrafanaSvc
	grafana.Name = assets.BusiSvcGrafana
	grafana.Port = "3000"
	grafana.RootDir = "/usr/share/grafana/"
	grafana.DataDir = "/var/lib/grafana/"
	grafana.LogDir = "/var/log/grafana/"
	grafana.ConfigDir = "/etc/grafana/"
	grafana.BinDir = "/usr/share/grafana/bin/grafana-server"

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
		svcInfo.RootDir = t.RootDir
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
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}

	// version
	/*
		bash-5.0$ grafana-cli -v
		Grafana CLI version 7.3.6
	*/
	versionCmd := []string{"grafana-cli", "-v"}
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

// Rsyslog
var regexSvcRsyslog = `^[^\s]*rsyslogd\s`
var regexSvcRsyslogVersion = `(?<=rsyslogd\s)[^,]+`
var regexSvcRsyslogConfigDir = `(?<=-config\s)[^\s]+`
var regexSvcRsyslogDataDir = `(?<=-storage\s)[^\s]+`
var regexSvcRsyslogLogDir = `(?<=-logpath\s)[^\s]+`

type RsyslogSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	ConfigDirRegex  *regexp2.Regexp
	DataDirRegex    *regexp2.Regexp
	LogDirRegex     *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	DataDir         string
	ConfigDir       string
	LogDir          string
}

func NewRsyslogSvc() ISvcDiscovery {
	var grafana RsyslogSvc
	grafana.Name = assets.BusiSvcRsyslog
	grafana.DataDir = "/var/lib/rsyslog/"
	grafana.LogDir = "/var/log/messages"
	grafana.ConfigDir = "/etc/" //  /etc/rsyslog.conf

	var err error
	grafana.SvcRegex, err = regexp2.Compile(regexSvcRsyslog, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslog)
		return nil
	}
	grafana.SvcVersionRegex, err = regexp2.Compile(regexSvcRsyslogVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslogVersion)
		return nil
	}
	grafana.ConfigDirRegex, err = regexp2.Compile(regexSvcRsyslogConfigDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslogConfigDir)
		return nil
	}
	grafana.DataDirRegex, err = regexp2.Compile(regexSvcRsyslogDataDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslogDataDir)
		return nil
	}
	grafana.LogDirRegex, err = regexp2.Compile(regexSvcRsyslogLogDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcRsyslogLogDir)
		return nil
	}
	return &grafana
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
			svcInfo.ConfigDir = match.String()
		}
		match, err = t.LogDirRegex.FindStringMatch(cmdStr)
		if err == nil && match != nil {
			svcInfo.LogDir = match.String()
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

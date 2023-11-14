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

// Tomcat
var regexSvcTomcat = "tomcat"
var regexSvcTomcatRootDir = []string{`(?<=-Dcatalina.base=)(.*)`, `(?<=-Dcatalina.home=)(.*)`}
var regexSvcTomcatPort = `(?<=<Connector port=")\d+(?=" protocol="HTTP/1.1")`
var regexSvcTomcatAccessLog = `(?<=directory=").*(?=")`
var regexSvcTomcatCatalinaLog = `(?<==).*`
var regexSvcTomcatVersion = `(?<=Version\s).*$`

type TomcatSvc struct {
	SvcRegex         *regexp2.Regexp
	RootDirRegex     *regexp2.Regexp
	PortRegex        *regexp2.Regexp
	AccessLogRegex   *regexp2.Regexp
	CatalinaLogRegex *regexp2.Regexp
	VersionRegex     *regexp2.Regexp
	Name             string // 服务类型
	Port             string
	RootDir          string // 主目录路径
	ConfigDir        string
	LogDir           string
}

func NewTomcatSvc() ISvcDiscovery {
	var tomcat TomcatSvc
	tomcat.Name = assets.BusiSvcTomcat
	tomcat.Port = "8080"
	tomcat.RootDir = "/usr/local/tomcat"
	var err error
	tomcat.SvcRegex, err = regexp2.Compile(regexSvcTomcat, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcTomcat)
		return nil
	}
	rootRegex := strings.Join(regexSvcTomcatRootDir, "|")
	tomcat.RootDirRegex, err = regexp2.Compile(rootRegex, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", rootRegex)
		return nil
	}
	tomcat.PortRegex, err = regexp2.Compile(regexSvcTomcatPort, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcTomcatPort)
		return nil
	}
	tomcat.AccessLogRegex, err = regexp2.Compile(regexSvcTomcatAccessLog, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcTomcatAccessLog)
		return nil
	}
	tomcat.CatalinaLogRegex, err = regexp2.Compile(regexSvcTomcatCatalinaLog, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcTomcatCatalinaLog)
		return nil
	}
	tomcat.VersionRegex, err = regexp2.Compile(regexSvcTomcatVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcTomcatVersion)
		return nil
	}
	return &tomcat
}
func (t *TomcatSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		binary, arg := parseCmdBySpace(cmd.cmdStr)
		if !strings.HasSuffix(binary, "java") {
			continue
		}
		for _, a := range arg {
			if svcInfo.Name == "" {
				isMatch, err := t.SvcRegex.MatchString(a)
				if err != nil || !isMatch {
					continue
				}
				svcInfo.Name = t.Name
				svcInfo.Cmd = cmd.cmdStr
				svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
				continue
			}
			if svcInfo.RootDir == "" {
				stringMatch, err := t.RootDirRegex.FindStringMatch(a)
				if err != nil || stringMatch == nil {
					continue
				}
				svcInfo.RootDir = stringMatch.String()
				svcInfo.ConfigDir = svcInfo.RootDir + "/conf"
				break
			}
		}
	}
	if svcInfo.Name == "" && svcInfo.RootDir == "" {
		return nil
	}
	if svcInfo.Name == "" && svcInfo.RootDir != "" {
		svcInfo.Name = t.Name
	} else if svcInfo.Name != "" && svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
		svcInfo.ConfigDir = t.ConfigDir
		svcInfo.LogDir = t.LogDir
	}
	// version
	/*
		root@webapps01:/usr/local/tomcat# cat $CATALINA_HOME/RELEASE-NOTES |grep "Apache Tomcat Version "
		                     Apache Tomcat Version 10.0.14
	*/
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	versionCmdList := []string{"/bin/bash", "-c", `cat $CATALINA_HOME/RELEASE-NOTES |grep "Apache Tomcat Version "`}
	output, err := runCmd(ctx, containerId, versionCmdList)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmdList)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmdList, output)
		match, err := t.VersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	// 解析配置文件
	// port
	ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
	portCmd := []string{"/bin/bash", "-c", `cat $CATALINA_HOME/conf/server.xml |grep "<Connector port"`}
	output, err = runCmd(ctx, containerId, portCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", portCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", portCmd, output)
		match, err := t.PortRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Port = match.String()
		}
	}
	// log:accessLog
	ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
	accessLogCmd := []string{"/bin/bash", "-c", `cat $CATALINA_HOME/conf/server.xml |grep "org.apache.catalina.valves.AccessLogValve"`}
	output, err = runCmd(ctx, containerId, accessLogCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", accessLogCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", accessLogCmd, output)
		match, err := t.AccessLogRegex.FindStringMatch(output)
		if err == nil && match != nil {
			tmp := match.String()
			if filepath.IsAbs(tmp) {
				svcInfo.LogDir = tmp
			} else {
				svcInfo.LogDir = filepath.Join(svcInfo.RootDir, tmp)
			}
		}
	}
	// catalinaLog
	ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
	catalinaLogCmd := []string{"/bin/bash", "-c", `cat $CATALINA_HOME/conf/logging.properties |grep "1catalina.org.apache.juli.AsyncFileHandler.directory"`}
	output, err = runCmd(ctx, containerId, catalinaLogCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", catalinaLogCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", catalinaLogCmd, output)
		match, err := t.CatalinaLogRegex.FindStringMatch(output)
		if err == nil && match != nil {
			catalinaLogDir := strings.TrimSpace(match.String())
			catalinaLogDir = strings.ReplaceAll(catalinaLogDir, "${catalina.base}", svcInfo.RootDir)
			if catalinaLogDir != svcInfo.LogDir {
				if svcInfo.LogDir != "" {
					svcInfo.LogDir += ","
				}
				svcInfo.LogDir += catalinaLogDir
			}
		}
	}
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}
	if svcInfo.LogDir == "" {
		svcInfo.LogDir = filepath.Join(t.RootDir, "/logs")
	}
	return &svcInfo
}

// Apache
var regexSvcApache = "httpd -dforeground"
var regexSvcApacheVersion = `(?<=Apache\/)[^ ]+`
var regexSvcApacheConfPath = `(?<=SERVER_CONFIG_FILE=").*(?=")`
var regexSvcApacheLogPath = `(?<=DEFAULT_ERRORLOG=").*(?=")`
var regexSvcApacheRootDir = `(?<=HTTPD_ROOT=").*(?=")`
var regexSvcApachePort = `(?<=Listen\s).*`

type ApacheSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	SvcConfRegex    *regexp2.Regexp
	SvcLogRegex     *regexp2.Regexp
	SvcRootDirRegex *regexp2.Regexp
	SvcPortRegex    *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	ConfigDir       string
	LogDir          string
}

func NewApacheSvc() ISvcDiscovery {
	var apache ApacheSvc
	apache.Name = assets.BusiSvcAppache
	apache.Port = "80"
	apache.RootDir = "/usr/local/apache2"
	var err error
	apache.SvcRegex, err = regexp2.Compile(regexSvcApache, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcApache)
		return nil
	}
	apache.SvcVersionRegex, err = regexp2.Compile(regexSvcApacheVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcApacheVersion)
		return nil
	}
	apache.SvcConfRegex, err = regexp2.Compile(regexSvcApacheConfPath, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcApacheConfPath)
		return nil
	}
	apache.SvcLogRegex, err = regexp2.Compile(regexSvcApacheLogPath, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcApacheLogPath)
		return nil
	}
	apache.SvcRootDirRegex, err = regexp2.Compile(regexSvcApacheRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcApacheRootDir)
		return nil
	}
	apache.SvcPortRegex, err = regexp2.Compile(regexSvcApachePort, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcApachePort)
		return nil
	}

	return &apache
}
func (t *ApacheSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		isMatch, err := t.SvcRegex.MatchString(cmd.cmdStr)
		if err != nil || !isMatch {
			continue
		}
		svcInfo.Name = t.Name
		svcInfo.Cmd = cmd.cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		break
	}
	if svcInfo.Name == "" {
		return nil
	}
	// version
	/*
		root@webapps01-74b8f9855d-w7vzn:/usr/local/apache2# httpd -V
		Server version: Apache/2.4.52 (Unix)
		Server built:   Dec 21 2021 01:34:45
		Server's Module Magic Number: 20120211:121
		Server loaded:  APR 1.7.0, APR-UTIL 1.6.1
		Compiled using: APR 1.7.0, APR-UTIL 1.6.1
		Architecture:   64-bit
		Server MPM:     event
		 threaded:     yes (fixed thread count)
		   forked:     yes (variable process count)
		Server compiled with....
		-D APR_HAS_SENDFILE
		-D APR_HAS_MMAP
		-D APR_HAVE_IPV6 (IPv4-mapped addresses enabled)
		-D APR_USE_PROC_PTHREAD_SERIALIZE
		-D APR_USE_PTHREAD_SERIALIZE
		-D SINGLE_LISTEN_UNSERIALIZED_ACCEPT
		-D APR_HAS_OTHER_CHILD
		-D AP_HAVE_RELIABLE_PIPED_LOGS
		-D DYNAMIC_MODULE_LIMIT=256
		-D HTTPD_ROOT="/usr/local/apache2"
		-D SUEXEC_BIN="/usr/local/apache2/bin/suexec"
		-D DEFAULT_PIDLOG="logs/httpd.pid"
		-D DEFAULT_SCOREBOARD="logs/apache_runtime_status"
		-D DEFAULT_ERRORLOG="logs/error_log"
		-D AP_TYPES_CONFIG_FILE="conf/mime.types"
		-D SERVER_CONFIG_FILE="conf/httpd.conf"
	*/
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	apacheVersionCmd := []string{svcInfo.BinaryDir, "-V"}
	output, err := runCmd(ctx, containerId, apacheVersionCmd)
	cancelFunc()
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", apacheVersionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", apacheVersionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}

		match, err = t.SvcRootDirRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.RootDir = match.String()
		}

		match, err = t.SvcConfRegex.FindStringMatch(output)
		if err == nil && match != nil {
			path := match.String()
			if filepath.IsAbs(path) {
				svcInfo.ConfigDir = path
			} else {
				svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, path)
			}
		}

		match, err = t.SvcLogRegex.FindStringMatch(output)
		if err == nil && match != nil {
			path := match.String()
			if filepath.IsAbs(path) {
				svcInfo.LogDir = path
			} else {
				svcInfo.LogDir = filepath.Join(svcInfo.RootDir, path)
			}
		}
	}

	if svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
	}
	if svcInfo.LogDir == "" {
		svcInfo.LogDir = filepath.Join(cwd, "/logs")
	}
	if svcInfo.ConfigDir == "" {
		svcInfo.LogDir = filepath.Join(cwd, "/conf")
	} else {
		//	 port
		/*
			root@webapps01-74b8f9855d-w7vzn:/usr/local/apache2/logs# cat /usr/local/apache2/conf/httpd.conf |grep "^Listen"
			Listen 80
		*/
		ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
		apachePortCmd := []string{"/bin/bash", "-c", fmt.Sprintf(`cat %s |grep "^Listen"`, svcInfo.ConfigDir)}
		output, err = runCmd(ctx, containerId, apachePortCmd)
		cancelFunc()
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", apachePortCmd)
		} else {
			logging.Get().Info().Msgf("run cmd[%s] result:", apachePortCmd, output)
			match, err := t.SvcPortRegex.FindStringMatch(output)
			if err == nil && match != nil {
				svcInfo.Port = match.String()
			}
		}
	}
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}
	return &svcInfo
}

// Nginx
var regexSvcNginx = "nginx: master process nginx"
var regexSvcNginxVersion = `(?<=nginx/).*$`
var regexSvcNginxRootDir = `(?<=-p\s).*?(?=\s+)`
var regexSvcNginxConfPath = `(?<=-c\s).*?(?=\s+)`

type NginxSvc struct {
	SvcRegex         *regexp2.Regexp
	SvcVersionRegex  *regexp2.Regexp
	SvcRootDirRegex  *regexp2.Regexp
	SvcConfPathRegex *regexp2.Regexp
	Name             string // 服务类型
	Port             string
	RootDir          string // 主目录路径
	ConfigDir        string
	LogDir           string
}

func NewNginxSvc() ISvcDiscovery {
	var nginx NginxSvc
	nginx.Name = assets.BusiSvcNginx
	nginx.Port = "80"
	nginx.RootDir = "/etc/nginx"
	//nginx.ConfigDir = "/etc/nginx/nginx.conf"
	nginx.LogDir = "/var/log/nginx"
	var err error
	nginx.SvcRegex, err = regexp2.Compile(regexSvcNginx, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcNginx)
		return nil
	}
	nginx.SvcVersionRegex, err = regexp2.Compile(regexSvcNginxVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcNginxVersion)
		return nil
	}
	nginx.SvcRootDirRegex, err = regexp2.Compile(regexSvcNginxRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcNginxRootDir)
		return nil
	}
	nginx.SvcConfPathRegex, err = regexp2.Compile(regexSvcNginxConfPath, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcNginxConfPath)
		return nil
	}
	return &nginx
}
func (t *NginxSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		isMatch, err := t.SvcRegex.MatchString(cmd.cmdStr)
		if err != nil || !isMatch {
			continue
		}
		svcInfo.Name = t.Name
		svcInfo.Port = t.Port
		svcInfo.Cmd = cmd.cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		match, err := t.SvcRootDirRegex.FindStringMatch(cmd.cmdStr)
		if err == nil && match != nil {
			svcInfo.RootDir = match.String()
		}
		match, err = t.SvcConfPathRegex.FindStringMatch(cmd.cmdStr)
		if err == nil && match != nil {
			svcInfo.ConfigDir = match.String()
		}
		break
	}
	if svcInfo.Name == "" {
		return nil
	}
	svcInfo.LogDir = t.LogDir
	if svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
	}
	if svcInfo.ConfigDir == "" {
		svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "/nginx.conf")
	}

	// version
	//root@webapps02-5775c98965-dclgd:/etc/nginx# nginx -v
	//nginx version: nginx/1.21.5
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	apacheVersionCmd := []string{"nginx", "-v"}
	output, err := runCmd(ctx, containerId, apacheVersionCmd)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", apacheVersionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", apacheVersionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// Weblogic
var regexSvcWeblogic = "-Dweblogic.Name"
var regexSvcWeblogicVersion = `(?<=WebLogic Server\s)[^ ]+`
var regexSvcWeblogicRootDir = `(?<=-Dweblogic.home=).*$`

type WeblogicSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	ConfigDir       string
	LogDir          string
}

func NewWeblogicSvc() ISvcDiscovery {
	var nginx WeblogicSvc
	nginx.Name = assets.BusiSvcWeblogic
	nginx.Port = "7001"
	nginx.RootDir = "/u01/oracle/weblogic/wlserver/server"
	var err error
	nginx.SvcRegex, err = regexp2.Compile(regexSvcWeblogic, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWeblogic)
		return nil
	}
	nginx.SvcVersionRegex, err = regexp2.Compile(regexSvcWeblogicVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWeblogicVersion)
		return nil
	}
	nginx.RootDirRegex, err = regexp2.Compile(regexSvcWeblogicRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWeblogicRootDir)
		return nil
	}
	return &nginx
}

/*  以java命令启动，并且  包含`-Dweblogic.Name`参数*/
func (t *WeblogicSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		binary, arg := parseCmdBySpace(cmd.cmdStr)
		if !strings.HasSuffix(binary, "java") {
			continue
		}
		for _, a := range arg {
			if svcInfo.Name == "" {
				matchString, _ := t.SvcRegex.MatchString(a)
				if matchString {
					svcInfo.Name = t.Name
					svcInfo.Port = t.Port
					svcInfo.Cmd = cmd.cmdStr
					svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
				}
			}
			if svcInfo.RootDir == "" {
				match, _ := t.RootDirRegex.FindStringMatch(a)
				if match != nil {
					svcInfo.RootDir = match.String()
				}
			}
			if svcInfo.Name != "" && svcInfo.RootDir != "" {
				break
			}
		}
		if svcInfo.Name != "" {
			break
		}
	}
	if svcInfo.Name == "" {
		return nil
	}
	var jarPath string
	if svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
		return &svcInfo
	}
	// version
	/*
		[oracle@webapps02-5775c98965-dclgd lib]$ java -cp weblogic.jar  weblogic.version | grep "WebLogic Server"
		WebLogic Server 12.1.3.0.0  Wed May 21 18:53:34 PDT 2014 1604337
	*/
	jarPath = filepath.Join(svcInfo.RootDir, "/lib", "/weblogic.jar")
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	apacheVersionCmd := []string{"/bin/sh", "-c", "java -cp " + jarPath + " weblogic.version" + ` | grep "WebLogic Server"`}
	output, err := runCmd(ctx, containerId, apacheVersionCmd)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", apacheVersionCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", apacheVersionCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// Wildfly
var regexSvcWildfly = "wildfly"
var regexSvcWildflyVersion = `(?<=WildFly Full\s)[^\s]+`
var regexSvcWildflyRootDir = `(?<=-Djboss.home.dir=).*$`
var regexSvcWildflyPort = `(?<=jboss.http.port:).*(?=})`

type WildflySvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
	SvcPortRegex    *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	ConfigDir       string
	LogDir          string
}

func NewWildflySvc() ISvcDiscovery {
	var wildfly WildflySvc
	wildfly.Name = assets.BusiSvcWildfly
	wildfly.Port = "8080" // 8009 8080 8443 9990 9993 4712 4713
	wildfly.RootDir = "/opt/jboss/wildfly"
	var err error
	wildfly.SvcRegex, err = regexp2.Compile(regexSvcWildfly, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWildfly)
		return nil
	}
	wildfly.SvcVersionRegex, err = regexp2.Compile(regexSvcWildflyVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWildflyVersion)
		return nil
	}
	wildfly.RootDirRegex, err = regexp2.Compile(regexSvcWildflyRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWildflyRootDir)
		return nil
	}
	wildfly.SvcPortRegex, err = regexp2.Compile(regexSvcWildflyPort, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWildflyPort)
		return nil
	}
	return &wildfly
}

func (t *WildflySvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		binary, arg := parseCmdBySpace(cmd.cmdStr)
		if !strings.HasSuffix(binary, "java") {
			continue
		}
		for _, a := range arg {
			if svcInfo.Name == "" {
				matchString, _ := t.SvcRegex.MatchString(a)
				if matchString {
					svcInfo.Name = t.Name
					//svcInfo.Port = t.Port
					svcInfo.Cmd = cmd.cmdStr
					svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
				}
			}
			if svcInfo.RootDir == "" {
				matchString, _ := t.RootDirRegex.FindStringMatch(a)
				if matchString != nil {
					svcInfo.RootDir = matchString.String()
					svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "/standalone/configuration/standalone.xml")
					svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "/standalone/log/server.log")
				}
			}

			if svcInfo.Name != "" && svcInfo.RootDir != "" {
				break
			}
		}
		if svcInfo.Name != "" {
			break
		}
	}
	if svcInfo.Name == "" {
		return nil
	}

	if svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
		svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "/standalone/configuration/standalone.xml")
		svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "/standalone/log/server.log")
	} else {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFunc()

		shCmd := []string{"/bin/bash", "-c", fmt.Sprintf(`cat %s |grep "jboss.http.port"`, svcInfo.ConfigDir)}
		output, err := runCmd(ctx, containerId, shCmd)
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", shCmd)
		} else {
			logging.Get().Info().Msgf("run cmd[%s] result:%s", shCmd, output)
			match, err := t.SvcPortRegex.FindStringMatch(output)
			if err == nil && match != nil {
				svcInfo.Port = match.String()
			}
		}
	}
	if svcInfo.Port == "" {
		svcInfo.Port = t.Port
	}
	// version
	/*
		[jboss@webapps-wildfly-7578b79c67-x9g27 bin]$ ./standalone.sh -v
		=========================================================================

		  JBoss Bootstrap Environment

		  JBOSS_HOME: /opt/jboss/wildfly

		  JAVA: /usr/lib/jvm/java/bin/java

		  JAVA_OPTS:  -server -Xms64m -Xmx512m

		=========================================================================

		06:16:06,260 INFO  [org.jboss.modules] (main) JBoss Modules version 1.12.0.Final
		WildFly Full 25.0.0.Final (WildFly Core 17.0.1.Final)
	*/
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	shCmd := []string{"/bin/bash", "-c", filepath.Join(svcInfo.RootDir, "/bin", "standalone.sh") + ` -v | grep "WildFly Full"`}
	output, err := runCmd(ctx, containerId, shCmd)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", shCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", shCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// WebSphere
var regexSvcWebSphere = "-Dibm.websphere.internalClassAccessMode"
var regexSvcWebSphereVersion = `(?<=Version\s+)(\S.+)`
var regexSvcWebSphereRootDir = `(?<=-Dserver.root=).*$`

type WebSphereSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	ConfigDir       string
	LogDir          string
}

func NewWebSphereSvc() ISvcDiscovery {
	var wildfly WebSphereSvc
	wildfly.Name = assets.BusiSvcWebSphere
	wildfly.Port = "8080"
	wildfly.RootDir = "/opt/IBM/WebSphere/AppServer/profiles/AppSrv01"
	var err error
	wildfly.SvcRegex, err = regexp2.Compile(regexSvcWebSphere, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWebSphere)
		return nil
	}
	wildfly.SvcVersionRegex, err = regexp2.Compile(regexSvcWebSphereVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWebSphereVersion)
		return nil
	}
	wildfly.RootDirRegex, err = regexp2.Compile(regexSvcWebSphereRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcWebSphereRootDir)
		return nil
	}
	return &wildfly
}

func (t *WebSphereSvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		binary, arg := parseCmdBySpace(cmd.cmdStr)
		if !strings.HasSuffix(binary, "java") {
			continue
		}
		for _, a := range arg {
			if svcInfo.Name == "" {
				matchString, _ := t.SvcRegex.MatchString(a)
				if matchString {
					svcInfo.Name = t.Name
					svcInfo.Port = t.Port
					svcInfo.Cmd = cmd.cmdStr
					svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
				}
			}
			if svcInfo.RootDir == "" {
				matchString, _ := t.RootDirRegex.FindStringMatch(a)
				if matchString != nil {
					svcInfo.RootDir = matchString.String()
				}
			}
			if svcInfo.Name != "" && svcInfo.RootDir != "" {
				break
			}
		}
		if svcInfo.Name != "" {
			break
		}
	}
	if svcInfo.Name == "" {
		return nil
	}
	if svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
	}
	svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "/config")
	svcInfo.LogDir = filepath.Join(svcInfo.RootDir, "/log")
	// version
	/*
		[was@webapps02dclgd bin]$ /opt/IBM/WebSphere/AppServer/bin/versionInfo.sh  |grep -A1 "IBM WebSphere Application Server"
		Name                  IBM WebSphere Application Server
		Version               9.0.5.16
	*/

	shCmd := []string{"/bin/sh", "-c", filepath.Join(svcInfo.RootDir, "/bin", "/versionInfo.sh") + ` |grep -A1 "IBM WebSphere Application Server"`}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	output, err := runCmd(ctx, containerId, shCmd)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", shCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", shCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// OpenResty
var regexSvcOpenResty = `^(?=.*nginx: master\sprocess\s)(?=.*openresty).+$`
var regexSvcOpenRestyVersion = `(?<= openresty/)(.*)`
var regexSvcOpenRestyRootDir = `(?<=-p\s).*(\s?)`
var regexSvcOpenRestyConfDir = `(?<=-c\s).*(\s?)`

type OpenRestySvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
	ConfigPathRegex *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	ConfigDir       string
	LogDir          string
}

func NewOpenRestySvc() ISvcDiscovery {
	var wildfly OpenRestySvc
	wildfly.Name = assets.BusiSvcOpenResty
	wildfly.Port = "80"
	wildfly.RootDir = "/usr/local/openresty/nginx"
	var err error
	wildfly.SvcRegex, err = regexp2.Compile(regexSvcOpenResty, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcOpenResty)
		return nil
	}
	wildfly.SvcVersionRegex, err = regexp2.Compile(regexSvcOpenRestyVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcOpenRestyVersion)
		return nil
	}
	wildfly.RootDirRegex, err = regexp2.Compile(regexSvcOpenRestyRootDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcOpenRestyRootDir)
		return nil
	}
	wildfly.ConfigPathRegex, err = regexp2.Compile(regexSvcOpenRestyConfDir, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexSvcOpenRestyConfDir)
		return nil
	}
	return &wildfly
}

func (t *OpenRestySvc) SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo {
	var svcInfo assets.ContainerSvcInfo
	for _, cmd := range cmdList {
		isMatch, err := t.SvcRegex.MatchString(cmd.cmdStr)
		if err != nil || isMatch == false {
			continue
		}
		svcInfo.Name = t.Name
		svcInfo.Port = t.Port
		svcInfo.Cmd = cmd.cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		match, err := t.RootDirRegex.FindStringMatch(cmd.cmdStr)
		if err == nil && match != nil {
			svcInfo.RootDir = match.String()
		}
		match, err = t.ConfigPathRegex.FindStringMatch(cmd.cmdStr)
		if err == nil && match != nil {
			svcInfo.ConfigDir = match.String()
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
		svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "conf/nginx.conf")
	}
	svcInfo.ConfigDir = filepath.Join(svcInfo.RootDir, "logs/error.log")
	// version
	/*
		root@webapps-openresty-7fd874d75d-vj96r:/# openresty -V 2>&1 | grep "nginx version: openresty/"
		nginx version: openresty/1.19.9.1
	*/
	shCmd := []string{"/bin/sh", "-c", `openresty -V 2>&1 | grep "nginx version: openresty/"`}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	output, err := runCmd(ctx, containerId, shCmd)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", shCmd)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", shCmd, output)
		match, err := t.SvcVersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

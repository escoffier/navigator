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

// Tomcat
var regexSvcTomcat = "tomcat"
var regexSvcTomcatRootDir = []string{`(?<=-Dcatalina.base=)(.*)`, `(?<=-Dcatalina.home=)(.*)`}
var regexSvcTomcatVersion = `(?<=Version\s).*$`

type TomcatSvc struct {
	SvcRegex     *regexp2.Regexp
	RootDirRegex *regexp2.Regexp
	VersionRegex *regexp2.Regexp
	Name         string // 服务类型
	Port         string
	RootDir      string // 主目录路径
	ConfigDir    string
	LogDir       string
}

func NewTomcatSvc() ISvcDiscovery {
	var tomcat TomcatSvc
	tomcat.Name = assets.BusiSvcTomcat
	tomcat.Port = "8080"
	tomcat.RootDir = "/usr/local/tomcat"
	tomcat.ConfigDir = "/usr/local/tomcat/conf"
	tomcat.LogDir = "/usr/local/tomcat/logs"
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
				svcInfo.Port = t.Port
				svcInfo.Cmd = cmd.cmdStr
				svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
				continue
			}
			if svcInfo.RootDir == "" {
				stringMatch, err := t.SvcRegex.FindStringMatch(a)
				if err != nil || stringMatch == nil {
					continue
				}
				svcInfo.RootDir = stringMatch.String()
				svcInfo.LogDir = svcInfo.RootDir + "/log"
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
	defer cancelFunc()
	versionCmdList := []string{"/bin/bash", "-c", `cat $CATALINA_HOME/RELEASE-NOTES |grep "Apache Tomcat Version "`}
	output, err := runCmd(ctx, containerId, versionCmdList)
	if err != nil {
		logging.Get().Err(err).Msgf("run cmd[%s] failed.", versionCmdList)
	} else {
		logging.Get().Info().Msgf("run cmd[%s] result:%s", versionCmdList, output)
		match, err := t.VersionRegex.FindStringMatch(output)
		if err == nil && match != nil {
			svcInfo.Version = match.String()
		}
	}
	return &svcInfo
}

// Apache
var regexSvcApache = "httpd -dforeground"
var regexSvcApacheVersion = `(?<=Apache\/)[^ ]+`

type ApacheSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
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
	apache.ConfigDir = filepath.Join(apache.RootDir, "/conf")
	apache.LogDir = filepath.Join(apache.RootDir, "/logs")
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
		svcInfo.Port = t.Port
		svcInfo.Cmd = cmd.cmdStr
		svcInfo.BinaryDir = getBinaryPathByPid(cmd.pid)
		break
	}
	if svcInfo.Name == "" {
		return nil
	}
	if strings.Contains(cwd, "apache") {
		svcInfo.RootDir = cwd
		svcInfo.ConfigDir = filepath.Join(cwd, "/conf")
		svcInfo.LogDir = filepath.Join(cwd, "/logs")
	} else {
		svcInfo.RootDir = t.RootDir
		svcInfo.ConfigDir = t.ConfigDir
		svcInfo.LogDir = t.LogDir
	}
	// version
	//root@webapps01-7b45bc8dd4-clwvq:/usr/local# apachectl -v
	//Server version: Apache/2.4.52 (Unix)
	//Server built:   Dec 21 2021 01:34:45
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	apacheVersionCmd := []string{"apachectl", "-v"}
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

// Nginx
var regexSvcNginx = "nginx: master process nginx"
var regexSvcNginxVersion = `(?<=nginx/).*$`

type NginxSvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	ConfigDir       string
	LogDir          string
}

func NewNginxSvc() ISvcDiscovery {
	var nginx NginxSvc
	nginx.Name = assets.BusiSvcNginx
	nginx.Port = "80"
	nginx.RootDir = "/etc/nginx"
	//nginx.ConfigDir = "/etc/nginx/nginx.conf"
	nginx.ConfigDir = nginx.RootDir
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
		break
	}
	if svcInfo.Name == "" {
		return nil
	}

	if strings.Contains(cwd, "nginx") {
		svcInfo.RootDir = cwd
	} else {
		svcInfo.RootDir = t.RootDir
		svcInfo.ConfigDir = t.RootDir
		svcInfo.LogDir = t.LogDir
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

type WildflySvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
	Name            string // 服务类型
	Port            string
	RootDir         string // 主目录路径
	ConfigDir       string
	LogDir          string
}

func NewWildflySvc() ISvcDiscovery {
	var wildfly WildflySvc
	wildfly.Name = assets.BusiSvcWildfly
	wildfly.Port = "8080"
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
		return &svcInfo
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
		return &svcInfo
	}
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
var regexSvcOpenRestyRootDir = ``

type OpenRestySvc struct {
	SvcRegex        *regexp2.Regexp
	SvcVersionRegex *regexp2.Regexp
	RootDirRegex    *regexp2.Regexp
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
	wildfly.RootDir = "/usr/local/openresty"
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
		break
	}
	if svcInfo.Name == "" {
		return nil
	}
	if svcInfo.RootDir == "" {
		svcInfo.RootDir = t.RootDir
	}
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

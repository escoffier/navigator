package svcdiscovery

import (
	"context"
	"fmt"
	"github.com/dlclark/regexp2"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
	"strings"
	"time"
)

// Java
type JavaFramework struct {
	languageName            string
	languageRegex           *regexp2.Regexp
	languageVersionRegex    *regexp2.Regexp
	languageVersionCmdRegex *regexp2.Regexp
	frameworkRegex          *regexp2.Regexp
}

// eg:/usr/local/openjdk-11/bin/java   -jar myapp.jar
var regexpLanguageJava = ".*java$"
var regexpLangJavaVersionList = []string{
	"(?<=/jdk).*?(?=/)",      // /usr/java/jdk1.8.0_25/bin/java
	"(?<=/openjdk-).*?(?=/)", // /usr/local/openjdk-11/bin/java
}
var regexpLangJavaVersionCmd = `(?<=")[^"]+(?=")`
var regexJavaFramework = []string{"(?<=spring-core-).*(?=.jar)"}

func NewJava() *JavaFramework {
	var java JavaFramework
	var err error
	java.languageName = assets.BusiFrameworkJava
	java.languageRegex, err = regexp2.Compile(regexpLanguageJava, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguageJava)
		return nil
	}

	javaVersionRegex := strings.Join(regexpLangJavaVersionList, "|")
	java.languageVersionRegex, err = regexp2.Compile(javaVersionRegex, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", javaVersionRegex)
		return nil
	}
	javaFrameworkRegex := strings.Join(regexJavaFramework, "|")
	java.frameworkRegex, err = regexp2.Compile(javaFrameworkRegex, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", javaFrameworkRegex)
		return nil
	}

	java.languageVersionCmdRegex, err = regexp2.Compile(regexpLangJavaVersionCmd, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLangJavaVersionCmd)
		return nil
	}

	return &java
}

func (j *JavaFramework) FrameworkDiscovery(containerId string, cmdList []*cmdItem) *assets.ContainerFrameworkInfo {
	var framework assets.ContainerFrameworkInfo
	for _, cmd := range cmdList {
		binary, arg := parseCmdBySpace(cmd.cmdStr)
		isMatch, err := j.languageRegex.MatchString(binary)
		if err != nil {
			logging.Get().Err(err).Msgf("match language failed. binary:%s", binary)
			continue
		}
		if !isMatch {
			continue
		}
		framework.LanguageName = j.languageName
		framework.LanguageBinPath = getBinaryPathByPid(cmd.pid)
		// version try1: 父级目录
		stringMatch, err := j.languageVersionRegex.FindStringMatch(binary)
		if err != nil {
			logging.Get().Err(err).Msgf("match language failed.")
		}
		if stringMatch != nil {
			framework.LanguageVersion = stringMatch.String()
		}
		// version try2:  runCmd
		if framework.LanguageVersion == "" && runCmd != nil {
			ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := runCmd(ctx, containerId, []string{binary, "-version"})
			if err != nil {
				logging.Get().Err(err).Msgf("get language by cmd failed.")
			}
			cancelFunc()
			//java version "11.0.10" 2021-01-19 LTS
			//java version "1.8.0_371"
			logging.Get().Info().Msgf("java -version :%s", resp)
			match, err := j.languageVersionCmdRegex.FindStringMatch(resp)
			if err == nil && match != nil {
				framework.LanguageVersion = match.String()
			}
		}
		var jarName string
		for i, a := range arg {
			if a == "-jar" && i+2 < len(arg) {
				jarName = arg[i+1]
				break
			}
		}
		// framework try:
		//  1.java -jar /app.jar ;
		// 2.java -cp .;myClass.jar packname.mainclassname
		//  使用 jar tf /path/to/spring.jar | grep 'spring-core.*jar$'  ->   "BOOT-INF/lib/spring-core-5.1.3.RELEASE.jar"
		if jarName != "" && runCmd != nil {
			ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
			jarPath := strings.TrimSuffix(binary, "java") + "jar"
			resp, err := runCmd(ctx, containerId, []string{"/bin/sh", "-c", fmt.Sprintf(`%s tf %s | grep 'spring-core.*jar$'`, jarPath, jarName)})
			//logging.Get().Debug().Msgf("java framework   resp:%s,err is nil:%v, containerId:%s", resp, err == nil, containerId)
			if err != nil {
				logging.Get().Err(err).Msgf("get framework by cmd failed.")
			}
			cancelFunc()
			match, err := j.frameworkRegex.FindStringMatch(resp)
			if err != nil {
				logging.Get().Err(err).Msgf("match framework failed.")
			}
			if match != nil {
				framework.FrameworkName = "Spring"
				framework.FrameworkVersion = match.String()
				framework.FrameworkPath = jarName
			}
		}
		break
	}
	if framework.LanguageName == "" {
		return nil
	}
	return &framework
}

// Python
var regexpLanguagePython = `.*python(\d?)$`

// var pythonFramework = []string{"runserver"}
var regexpPythonVersion = `(?<=Python\s).*`

type PythonFramework struct {
	languageName         string
	languageRegex        *regexp2.Regexp
	languageVersionRegex *regexp2.Regexp
}

// Django
func NewPython() IFrameworkDiscovery {
	var python PythonFramework
	python.languageName = assets.BusiFrameworkPython
	var err error
	python.languageRegex, err = regexp2.Compile(regexpLanguagePython, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguagePython)
		return nil
	}
	python.languageVersionRegex, err = regexp2.Compile(regexpPythonVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpPythonVersion)
		return nil
	}
	return &python
}

func (p *PythonFramework) FrameworkDiscovery(containerId string, cmdList []*cmdItem) *assets.ContainerFrameworkInfo {
	var framework assets.ContainerFrameworkInfo
	for _, cmd := range cmdList {
		binary, argu := parseCmdBySpace(cmd.cmdStr)
		isMatch, err := p.languageRegex.MatchString(binary)
		if err != nil {
			logging.Get().Err(err).Msgf("match language failed. binary:%s", binary)
			continue
		}
		if !isMatch {
			continue
		}
		framework.LanguageName = p.languageName
		framework.LanguageBinPath = getBinaryPathByPid(cmd.pid)
		// langurage version
		/*
			root@python-django-6d74f6d468-8n9jk:/# python --version
			Python 2.7.9
		*/
		if runCmd != nil {
			ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := runCmd(ctx, containerId, []string{binary, "--version"})
			if err != nil {
				logging.Get().Err(err).Msgf("get framework by cmd failed.")
			}
			cancelFunc()
			match, err := p.languageVersionRegex.FindStringMatch(resp)
			if err != nil {
				logging.Get().Err(err).Msgf("match framework failed.")
			}
			if match != nil {
				framework.LanguageVersion = match.String()
			}
		}
		for _, a := range argu {
			if strings.Contains(a, ".py") {
				framework.FrameworkPath = a
			}
			if a == "runserver" {
				framework.FrameworkName = "Django"
				break
			}
		}
		if framework.FrameworkName == "" {
			framework.FrameworkPath = ""
			break
		}

		if framework.FrameworkName == "Django" {
			//	version
			/*
				root@python-django-6d74f6d468-8n9jk:/# django-admin --version
				1.10.7
			*/
			ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelFunc()

			djangoVersionCmd := []string{"django-admin", "--version"}
			output, err := runCmd(ctx, containerId, djangoVersionCmd)
			if err != nil {
				logging.Get().Err(err).Msgf("run cmd[%s] failed.", djangoVersionCmd)
			} else {
				logging.Get().Info().Msgf("run cmd[%s] result:%s", djangoVersionCmd, output)
				framework.FrameworkVersion = output
			}
		}
		break
	}
	if framework.LanguageName == "" {
		return nil
	}
	return &framework
}

// PHP
var regexpLanguagePhp = ".*php$"
var regexpLanguagePhpVersion = `(?<=PHP\s)\S+`
var regexPhpFrameworkVersionCmd = `(?<=Symfony\s)[^\s]+`
var regexPhpFramework = ".*bin/console$"

type PhpFramework struct {
	languageName          string
	languageRegex         *regexp2.Regexp
	languageVersionRegex  *regexp2.Regexp
	frameworkRegex        *regexp2.Regexp
	frameworkVersionRegex *regexp2.Regexp
}

func NewPhp() IFrameworkDiscovery {
	var php PhpFramework
	php.languageName = assets.BusiFrameworkPhp

	var err error
	php.languageRegex, err = regexp2.Compile(regexpLanguagePhp, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguagePhp)
		return nil
	}
	php.languageVersionRegex, err = regexp2.Compile(regexpLanguagePhpVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguagePhpVersion)
		return nil
	}
	php.frameworkRegex, err = regexp2.Compile(regexPhpFramework, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexPhpFramework)
		return nil
	}
	php.frameworkVersionRegex, err = regexp2.Compile(regexPhpFrameworkVersionCmd, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexPhpFramework)
		return nil
	}
	return &php
}

// php /var/www/bin/console server:run 0.0.0.0:8080
func (p *PhpFramework) FrameworkDiscovery(containerId string, cmdList []*cmdItem) *assets.ContainerFrameworkInfo {
	var framework assets.ContainerFrameworkInfo
	frameworkPath := ""
	for _, cmd := range cmdList {
		binary, argu := parseCmdBySpace(cmd.cmdStr)
		isMatch, err := p.languageRegex.MatchString(binary)
		if err != nil {
			logging.Get().Err(err).Msgf("match language failed. binary:%s", binary)
			continue
		}
		if !isMatch {
			continue
		}
		framework.LanguageName = p.languageName
		framework.LanguageBinPath = getBinaryPathByPid(cmd.pid)
		/*
			root@php-symfony-85548865c7-kgwk4:/# php -v |grep '^PHP'
			PHP 7.3.10 (cli) (built: Oct  4 2019 22:20:02) ( NTS )
		*/
		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		phpVersionCmd := []string{"/bin/bash", "-c", binary + ` -v |grep '^PHP'`}
		output, err := runCmd(ctx, containerId, phpVersionCmd)
		cancelFunc()
		logging.Get().Info().Msgf("php version  output:%s, err is nil:%v, containerId:%s", output, err == nil, containerId)
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", phpVersionCmd)
		} else {
			match, err := p.languageVersionRegex.FindStringMatch(output)
			if err == nil && match != nil {
				framework.LanguageVersion = match.String()
			}
		}
		for _, a := range argu {
			isMatch, err = p.frameworkRegex.MatchString(a)
			if err == nil && isMatch {
				framework.FrameworkName = "Symfony "
				frameworkPath = a
				break
			}
		}
		if framework.FrameworkName == "" {
			break
		}
		framework.FrameworkPath = argu[0]
		//version
		/*
			root@php-symfony-85548865c7-kgwk4:/# php /var/www/bin/console --version
			Symfony 3.4.35 (kernel: app, env: dev, debug: true)
		*/
		ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
		djangoVersionCmd := []string{"php", frameworkPath, "--version"}
		output, err = runCmd(ctx, containerId, djangoVersionCmd)
		cancelFunc()
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", djangoVersionCmd)
		} else {
			//logging.Get().Info().Msgf("run cmd[%s] result:%s", djangoVersionCmd, output)
			match, err := p.frameworkVersionRegex.FindStringMatch(output)
			if err == nil && match != nil {
				framework.FrameworkVersion = match.String()
			}
		}

		break
	}
	if framework.LanguageName == "" {
		return nil
	}
	return &framework
}

// .Net /usr/bin/mono /usr/lib/mono/4.5/fastcgi-mono-server4.exe /applications=/:/usr/aspnet/ /socket=tcp:127.0.0.1:9000
var regexpLanguageNet = `^[^\s]*mono$`
var regexpLanguageNetVersion = `(?<=version\s)\S+`
var regexNetFramework = `aspnet`

type NetFramework struct {
	languageName         string
	languageRegex        *regexp2.Regexp
	languageVersionRegex *regexp2.Regexp
	frameworkRegex       *regexp2.Regexp
}

func NewNet() IFrameworkDiscovery {
	var netf NetFramework
	netf.languageName = assets.BusiFrameworkNet
	var err error
	netf.languageRegex, err = regexp2.Compile(regexpLanguageNet, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguageNet)
		return nil
	}
	netf.languageVersionRegex, err = regexp2.Compile(regexpLanguageNetVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguageNetVersion)
		return nil
	}
	netf.frameworkRegex, err = regexp2.Compile(regexNetFramework, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexNetFramework)
		return nil
	}
	return &netf
}

func (p *NetFramework) FrameworkDiscovery(containerId string, cmdList []*cmdItem) *assets.ContainerFrameworkInfo {
	var framework assets.ContainerFrameworkInfo
	for _, cmd := range cmdList {
		binary, argu := parseCmdBySpace(cmd.cmdStr)
		isMatch, err := p.languageRegex.MatchString(binary)
		if err != nil {
			logging.Get().Err(err).Msgf("match language failed. binary:%s", binary)
			continue
		}
		if !isMatch {
			continue
		}
		framework.LanguageName = p.languageName
		framework.LanguageBinPath = getBinaryPathByPid(cmd.pid)
		// version
		/*
			bash-4.1# mono -V | grep version
			Mono JIT compiler version 3.6.1 (master/f6da699 Thu Jun 26 22:41:45 BST 2014)
		*/
		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFunc()
		monoVersionCmd := []string{"/bin/bash", "-c", binary + ` -V |grep version`}
		output, err := runCmd(ctx, containerId, monoVersionCmd)
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", monoVersionCmd)
		} else {
			match, err := p.languageVersionRegex.FindStringMatch(output)
			if err == nil && match != nil {
				framework.LanguageVersion = match.String()
			}
		}
		// framework
		for _, a := range argu {
			isMatch, err = p.frameworkRegex.MatchString(a)
			if err == nil && isMatch {
				framework.FrameworkName = "ASP.net"
				break
			}
		}
		if framework.FrameworkName != "" {
			framework.FrameworkPath = argu[0]
		}
		break
	}
	if framework.LanguageName == "" {
		return nil
	}

	return &framework
}

// ruby    eg:ruby bin/rails server
var regexpLanguageRuby = `^[^\s]*ruby`
var regexpLanguageRubyVersion = `(?<=ruby\s)\S+`
var regexpRubyFramework = `^[^\s]*rails` //Rails
var regexpFrameworkRailsVersion = `(?<=Rails\s)\S+`

type RubyFramework struct {
	languageName          string
	languageRegex         *regexp2.Regexp
	languageVersionRegex  *regexp2.Regexp
	frameworkRegex        *regexp2.Regexp
	frameworkVersionRegex *regexp2.Regexp
}

func NewRuby() IFrameworkDiscovery {
	var ruby RubyFramework
	ruby.languageName = assets.BusiFrameworkRuby
	var err error
	ruby.languageRegex, err = regexp2.Compile(regexpLanguageRuby, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguageRuby)
		return nil
	}
	ruby.languageVersionRegex, err = regexp2.Compile(regexpLanguageRubyVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguageRubyVersion)
		return nil
	}
	ruby.frameworkRegex, err = regexp2.Compile(regexpRubyFramework, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpRubyFramework)
		return nil
	}
	ruby.frameworkVersionRegex, err = regexp2.Compile(regexpFrameworkRailsVersion, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpFrameworkRailsVersion)
		return nil
	}
	return &ruby
}

func (p *RubyFramework) FrameworkDiscovery(containerId string, cmdList []*cmdItem) *assets.ContainerFrameworkInfo {
	var framework assets.ContainerFrameworkInfo
	for _, cmd := range cmdList {
		binary, argus := parseCmdBySpace(cmd.cmdStr)
		isMatch, err := p.languageRegex.MatchString(binary)
		if err != nil {
			logging.Get().Err(err).Msgf("match language failed. binary:%s", binary)
			continue
		}
		if !isMatch {
			continue
		}
		framework.LanguageName = p.languageName
		framework.LanguageBinPath = getBinaryPathByPid(cmd.pid)
		// version
		/*
			root@ruby-rails-c74474cb8-kst84:/src/app# ruby -v
			ruby 2.3.3p222 (2016-11-21 revision 56859) [x86_64-linux]
		*/
		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		monoVersionCmd := []string{binary, `-v`}
		output, err := runCmd(ctx, containerId, monoVersionCmd)
		cancelFunc()
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", monoVersionCmd)
		} else {
			match, err := p.languageVersionRegex.FindStringMatch(output)
			if err == nil && match != nil {
				framework.LanguageVersion = match.String()
			}
		}
		// framework
		var railsBinaryPath string
		for i, argu := range argus {
			if i == 0 {
				framework.FrameworkPath = argu
			}
			match, err := p.frameworkRegex.MatchString(argu)
			if err == nil && match {
				framework.FrameworkName = "Rails"
				railsBinaryPath = argu
			}
		}
		if framework.FrameworkName == "" {
			break
		}
		framework.FrameworkPath = argus[0]
		/*
			root@ruby-rails-c74474cb8-kst84:/src/app# bin/rails -v
			Expected string default value for '--rc'; got false (boolean)
			Rails 4.1.5
		*/
		ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
		frameworkCmd := []string{railsBinaryPath, `-v`}
		output, err = runCmd(ctx, containerId, frameworkCmd)
		cancelFunc()
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", monoVersionCmd)
		} else {
			match, err := p.frameworkVersionRegex.FindStringMatch(output)
			if err == nil && match != nil {
				framework.FrameworkVersion = match.String()
			}
		}
		logging.Get().Info().Msgf("containerId:%s,framework:%v", containerId, framework)
		break
	}
	if framework.LanguageName == "" {
		return nil
	}
	return &framework
}

// node.js    eg:node /usr/local/bin/sails lift
var regexpLanguageNodejs = `^[^\s]*node\s`
var regexpNodejsFramework = `^[^\s]*sails` //Rails

type NodejsFramework struct {
	languageName   string
	languageRegex  *regexp2.Regexp
	frameworkRegex *regexp2.Regexp
}

func NewNodejs() IFrameworkDiscovery {
	var nodejs NodejsFramework
	nodejs.languageName = assets.BusiFrameworkNodejs
	var err error
	nodejs.languageRegex, err = regexp2.Compile(regexpLanguageNodejs, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpLanguageNodejs)
		return nil
	}
	nodejs.frameworkRegex, err = regexp2.Compile(regexpNodejsFramework, regexp2.IgnoreCase)
	if err != nil {
		logging.Get().Err(err).Msgf("regexp compile failed. [%s]", regexpNodejsFramework)
		return nil
	}
	return &nodejs
}

func (p *NodejsFramework) FrameworkDiscovery(containerId string, cmdList []*cmdItem) *assets.ContainerFrameworkInfo {
	var framework assets.ContainerFrameworkInfo
	for _, cmd := range cmdList {
		binary, argus := parseCmdBySpace(cmd.cmdStr)
		isMatch, err := p.languageRegex.MatchString(binary)
		if err != nil {
			logging.Get().Err(err).Msgf("match language failed. binary:%s", binary)
			continue
		}
		if !isMatch {
			continue
		}
		framework.LanguageName = p.languageName
		framework.LanguageBinPath = getBinaryPathByPid(cmd.pid)
		// version
		/*
			root@nodejs-sailsjs-79978bf79b-lkm8l:/proc# node -v
			v12.13.0
		*/
		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		monoVersionCmd := []string{binary, `-v`}
		output, err := runCmd(ctx, containerId, monoVersionCmd)
		cancelFunc()
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", monoVersionCmd)
		} else {
			framework.LanguageVersion = output
		}
		// framework
		var railsBinaryPath string
		for _, argu := range argus {
			match, err := p.frameworkRegex.MatchString(argu)
			if err == nil && match {
				framework.FrameworkName = "Sails.js"
				railsBinaryPath = argu
				break
			}
		}
		if framework.FrameworkName == "" {
			break
		}
		framework.FrameworkPath = argus[0]
		/*
			root@nodejs-sailsjs-79978bf79b-lkm8l:/proc# /usr/local/bin/sails -v
			1.2.3
		*/
		ctx, cancelFunc = context.WithTimeout(context.Background(), 5*time.Second)
		frameworkCmd := []string{railsBinaryPath, `-v`}
		output, err = runCmd(ctx, containerId, frameworkCmd)
		cancelFunc()
		if err != nil {
			logging.Get().Err(err).Msgf("run cmd[%s] failed.", monoVersionCmd)
		} else {
			framework.FrameworkVersion = output
		}
		logging.Get().Info().Msgf("containerId:%s,framework:%v", containerId, framework)
		break
	}
	if framework.LanguageName == "" {
		return nil
	}
	return &framework
}

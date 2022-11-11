package utils

import (
	"fmt"
	"os"
	"strings"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func GenFixSuggestion(sensitives []model.Sensitive, osString string, vulns []*model.Vuln) []string {
	// 生成敏感文件的建议
	suggests := make([]string, 0)
	sug := GenSensitiveFileSuggest(sensitives)
	if sug != "" {
		suggests = append(suggests, sug)
	}

	// 生成漏洞的建议
	sug = GenVulnSuggest(osString, vulns)
	if sug != "" {
		suggests = append(suggests, sug)
	}
	return suggests
}

// 生成敏感文件的修复建议
func GenSensitiveFileSuggest(files []model.Sensitive) string {
	pre := []string{"建议在镜像中移除以下敏感文件，然后重新打包镜像："}
	res := make([]string, 0)
	for i := range files {
		file := files[i]
		if file.Name == "" {
			continue
		}
		if !strings.HasPrefix("/", file.Name) {
			file.Name = "/" + file.Name
		}

		res = append(res, file.Name)
	}
	res = util.DeDuplicationStringSlice(res)
	if len(res) > 0 {
		pre = append(pre, res...)
		return strings.Join(pre, "\n")
	}
	return ""
}

// 生成漏洞的修复建议
func GenVulnSuggest(osstring string, vulns []*model.Vuln) string {
	split := strings.Split(osstring, ":")
	if len(split) == 0 || split[0] == "" {
		return ""
	}

	ans := make([]string, 0)

	for i := range vulns {
		if vulns[i].FixedBy != "" && vulns[i].Class == report.ClassOSPkg {
			ans = append(ans, vulns[i].PkgName)
		}
	}
	// 去重
	ans = util.DeDuplicationStringSlice(ans)
	install := InstallType(split[0])

	pre := "建议在Dockerfile里面使用以下命令升级软件包：\n"

	if len(ans) > 0 && install != "" {
		return fmt.Sprintf("%s%s %s", pre, install, strings.Join(ans, " "))
	}
	return ""
}

func InstallType(osFamily string) string {
	switch strings.ToLower(osFamily) {
	case "ubuntu", "debian":
		return "apt-get update  &&  apt upgrade -y "
	case "centos", "fedora":
		return "yum upgrade -y "
	case "alpine":
		return "apk update && apk add --upgrade -y "
	}
	return ""
}

func MkdirIfNotExist(path string, remove bool) error {
	if remove {
		// 先删除
		_ = os.RemoveAll(path)
	}

	stat, err := os.Stat(path)
	if err == nil {
		if stat.IsDir() {
			return nil
		} else {
			// 先删除这个文件再创建
			logging.GetLogger().Info().Str("filename", path).Msg("file exist remove it")
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Mkdir(path, os.ModePerm)
		}
	}
	if os.IsNotExist(err) {
		return os.Mkdir(path, os.ModePerm)
	}
	return err
}

func InANotInB(a []*model.Vuln, b []model.ExportVulnImage) []*model.Vuln {
	if len(a) == 0 || len(b) == 0 {
		return a
	}
	mapB := make(map[uint64]struct{})
	for i := range b {
		mapB[b[i].UniqueVuln] = struct{}{}
	}
	ans := make([]*model.Vuln, 0)
	for k := range a {
		if _, ok := mapB[a[k].UniqueVuln]; !ok {
			ans = append(ans, a[k])
		}
	}
	return ans
}

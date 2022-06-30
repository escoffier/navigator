package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 生成敏感文件的修复建议
func GenSensitiveFileSuggest(files []model.Sensitive) string {
	pre := "请确认相关文件是否存在风险，确认后在Dockerfile中删除异常文件："
	res := make([]string, 0)
	for i := range files {
		res = append(res, files[i].Name)
	}
	res = util.DeDuplicationStringSlice(res)
	if len(res) > 0 {
		return fmt.Sprintf("%s%s", pre, strings.Join(res, ";"))
	}
	return ""
}

// 生成漏洞的修复建议
func GenVulnSuggest(osstring string, vulns []*model.Vuln) string {
	imageOs := new(ftypes.OS)
	if err := json.Unmarshal([]byte(osstring), imageOs); err != nil {
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
	install := InstallType(imageOs)

	pre := "请在该镜像的Dockerfile中增加如下代码，以修复存在安全问题的软件：RUN "

	if len(ans) > 0 && install != "" {
		return fmt.Sprintf("%s %s %s", pre, install, strings.Join(ans, " "))
	}
	return ""
}

func InstallType(os *ftypes.OS) string {
	switch strings.ToLower(os.Family) {
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

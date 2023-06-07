package component

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/sdk/palace"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

type ReasonAndDetail struct {
	RejectReason int64
	RejectDetail string
	VulnScore    int64
	VulnLevel    string
	Action       string // 下一期需求
}

// interval 表示时间间隔,多少分钟，
func generateUUID(img model.ImageList, msgType string, interval int) uint64 {
	now, t := time.Now().UTC(), time.Now().UTC()
	if interval > 0 && interval < 60 {
		minute := now.Minute()
		t = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), interval*(minute/interval), 0, 0, time.UTC)
	}
	msg := fmt.Sprintf("%s-%s-%s-%s-%s", img.Library, img.FullRepoName, img.Tags, msgType, t.String())
	return uuid.GenerateUUIDFromString(msg)
}

// getFullRepoNameTagFromContainer returns the registry location, repository name, and tag
func getLibRepoTag(image string) (string, string, string) {
	// image: 192.168.1.203:5000/tensorsec-console:latest
	repositoryTag := strings.Split(image, ":")
	if len(repositoryTag) <= 1 {
		return "", "", ""
	}
	repository := strings.Join(repositoryTag[0:len(repositoryTag)-1], ":")
	tag := repositoryTag[len(repositoryTag)-1]
	pos := strings.IndexByte(repository, '/')
	if pos >= 0 && pos < len(repository)-1 {
		return repository[0:pos], repository[pos+1:], tag
	}
	return "", "", ""
}

func mergeRecord(reds ...[]ReasonAndDetail) []ReasonAndDetail {
	res := make([]ReasonAndDetail, 0)
	for i := range reds {
		for j := range reds[i] {
			res = append(res, reds[i][j])
		}
	}
	return res
}

func mergeMsg(reds ...[]model.KVHashs) []model.KVHashs {
	res := make([]model.KVHashs, 0)
	for i := range reds {
		for j := range reds[i] {
			res = append(res, reds[i][j])
		}
	}
	return res
}

type checkImageRes struct {
	Safe    bool
	Records []ReasonAndDetail
	Msg     []model.KVHashs
	Image   *model.ImageList
}

type checkSanImageRes struct {
	Safe     bool
	Records  []ReasonAndDetail
	Msg      []model.KVHashs
	ScanImag *model.ScanImage
}

var (
	LanguageMap = map[string]string{
		"bundler":      "Ruby",
		"pipenv":       "Python",
		"gemfile":      "Ruby",
		"pipfile":      "Python",
		"poetry":       "Python",
		"composer":     "PHP",
		"package-lock": "Node.js",
		"yarn":         "Node.js",
		"jar":          "Java",
		"war":          "Java",
		"ear":          "Java",
		"gobinary":     "GO",
		"gemspec":      "Ruby",
		"node-pkg":     "Node.js",
		"npm":          "Node.js",
		"python-pkg":   "Python",
		"cargo":        "Rust",
		"pom":          "Java",
		"nuget":        ".NET",
		"pip":          "Python",
		"gomod":        "GO",
	}
)

func CalculateVulnScore(imascan model.ScanImage, cus map[string]model.RejectVuln, ignoreNotFixedVuln, ignoreLangVuln bool) int {
	// 就先写魔法数字吧，恶心是恶心了点
	subScore := map[string]int{
		model.SeverityCritical:   25,
		model.SeverityHigh:       20,
		model.SeverityMedium:     15,
		model.SeverityLow:        10,
		model.SeverityNegligible: 5,
		model.SeverityUnknown:    5,
	}

	exitScore := map[string]bool{
		model.SeverityCritical:   false,
		model.SeverityHigh:       false,
		model.SeverityMedium:     false,
		model.SeverityLow:        false,
		model.SeverityNegligible: false,
		model.SeverityUnknown:    false,
	}
	ans := 50
	for _, vu := range imascan.VulnInfo {
		if (ignoreNotFixedVuln && vu.FixedBy == "") || (ignoreLangVuln && util.ExistBit1(vu.Flag, model.VulnFlagClassLangPkg)) {
			continue
		}

		if ignoreNotFixedVuln && vu.FixedBy == "" {
			continue
		}
		if cu, ok := cus[vu.Name]; ok && cu.RejectPolicy == model.RejectPolicyIgnore {
			continue
		}
		if !exitScore[vu.Severity] {
			ans -= subScore[vu.Severity]
			exitScore[vu.Severity] = true
		}
	}
	return ans
}

func compareSeverity(s1, s2 string) bool {
	subScore := map[string]int64{
		model.SeverityCritical:   6,
		model.SeverityHigh:       5,
		model.SeverityMedium:     4,
		model.SeverityLow:        3,
		model.SeverityNegligible: 2,
		model.SeverityUnknown:    1,
	}
	return subScore[s1] >= subScore[s2]
}

// 发送消息到事件中心
func sendMsgToEventCenter(ctx context.Context, reqBody model.ReqBody, image model.ImageList, palaceHandler *palace.Palace) error {

	ruleKey := palace.RuleKey{
		Name:     reqBody.RuleKey.Name,
		Category: reqBody.RuleKey.Category,
	}
	fullRepoName := palace.Scope{
		Kind: palace.ScopeKindRepo,
		Name: image.FullRepoName,
	}
	tag := palace.Scope{
		Kind: palace.ScopeKindTag,
		Name: image.Tags,
	}
	library := palace.Scope{
		Kind: palace.ScopeKindRegistry,
		Name: image.Library,
	}
	msg := map[string]interface{}{}

	for i := range reqBody.NotifyContext.CustomKV {
		kv := reqBody.NotifyContext.CustomKV[i].KVHash.EN
		msg[kv.Key] = kv.Value
	}

	if err := palaceHandler.SendSignal(ruleKey, []palace.Scope{fullRepoName, tag, library}, msg); err != nil {
		logging.GetLogger().Err(err).Msg("sendMsgToEventCenter.SendSignal")
		return err
	}
	logging.GetLogger().Info().Str("Image", fmt.Sprintf("%s/%s:%s", image.Library, image.FullRepoName, image.Tags)).Msg("sendMsgToEventCenter.SendSignal")

	return nil
}

func holaPartialTag(word string) string {
	return fmt.Sprintf("{%s}", word)
}

func checkRejectPolicy(po model.RejectPolicy) error {
	if len([]rune(po.Name)) > 15 || po.Name == "" {
		return errors.New("策略的名不能为空且不超过15个字符")
	}

	if len(po.Library) == 0 {
		return errors.New("未设置策略生效仓库")
	}

	if len([]rune(po.Comment)) > 100 {
		return errors.New("策略备注信息不超过100个字符")
	}

	if po.VulnPolicy != model.RejectPolicyAlarm && po.VulnPolicy != model.RejectPolicyReject {
		return errors.New("no vuln policy")
	}

	if po.VulnScore > 50 || po.VulnScore < 0 {
		return errors.New("漏洞分数不得为负数，也不能超过50分")
	}

	if l := model.GetSeverityRejectReason(po.VulnLevel); l <= 0 {
		return errors.New("漏洞阻断的级别设置不正确")
	}

	if len(po.RejectVulns) > 0 {
		for i := range po.RejectVulns {
			vu := po.RejectVulns[i]
			if vu.RejectPolicy != model.RejectPolicyIgnore && vu.RejectPolicy != model.RejectPolicyReject && vu.RejectPolicy != model.RejectPolicyAlarm {
				return errors.New("no customize vuln policy")
			}
			if vu.Name == "" {
				return errors.New("no customize vuln name")
			}
		}
	}

	if po.SensitiveFilePolicy != model.RejectPolicyAlarm && po.SensitiveFilePolicy != model.RejectPolicyReject && po.SensitiveFilePolicy != model.RejectPolicyIgnore {
		return errors.New("no SensitiveFile policy")
	}

	if po.MaliciousPolicy != model.RejectPolicyAlarm && po.MaliciousPolicy != model.RejectPolicyReject && po.MaliciousPolicy != model.RejectPolicyIgnore {
		return errors.New("no Virus policy")
	}

	if po.WebShellPolicy != model.RejectPolicyAlarm && po.WebShellPolicy != model.RejectPolicyReject {
		return errors.New("no webshell policy")
	}

	if po.TrustedImagePolicy != model.RejectPolicyAlarm && po.TrustedImagePolicy != model.RejectPolicyReject {
		return errors.New("no trusted imagepolicy")
	}

	if po.PrivilegedBootPolicy != model.RejectPolicyAlarm && po.PrivilegedBootPolicy != model.RejectPolicyReject {
		return errors.New("no privileged boot policy")
	}
	if po.EnvPolicy != model.RejectPolicyAlarm && po.EnvPolicy != model.RejectPolicyReject && po.EnvPolicy != model.RejectPolicyIgnore {
		return errors.New("no env policy")
	}
	webshellLevels := strings.Split(po.WebshellLevel, ",")
	for k := range webshellLevels {
		if webshellLevels[k] != scannermodel.WebshellLevelCertainly && webshellLevels[k] != scannermodel.WebshellLevelMaybe {
			return errors.New("webshell严重等级设置不正确，有certainly和maybe两项")
		}
	}

	if po.BaseImagePolicy != model.RejectPolicyAlarm && po.BaseImagePolicy != model.RejectPolicyReject {
		return errors.New("no base image policy")
	}

	return nil
}

func rejectPolicyToUpdater(po model.RejectPolicy) map[string]interface{} {
	bys, _ := json.Marshal(po.Library)

	updater := map[string]interface{}{
		"name":                   po.Name,
		"library_json":           bys,
		"comment":                po.Comment,
		"operator":               po.Operator,
		"vuln_score":             po.VulnScore,
		"vuln_level":             po.VulnLevel,
		"webshell_level":         po.WebshellLevel,
		"web_shell_score":        po.WebShellScore,
		"web_shell_policy":       po.WebShellPolicy,
		"sensitive_file_policy":  po.SensitiveFilePolicy,
		"malicious_policy":       po.MaliciousPolicy,
		"trusted_image_policy":   po.TrustedImagePolicy,
		"privileged_boot_policy": po.PrivilegedBootPolicy,
		"base_image_policy":      po.BaseImagePolicy,
		"enable":                 po.Enable,
		"vuln_policy":            po.VulnPolicy,
		"cicd_enable":            po.CicdEnable,
		"k8s_enable":             po.K8sEnable,
		"online_monitor":         po.OnlineMonitor,
		"mode":                   po.Mode,
		"env_policy":             po.EnvPolicy,
		"ignore_not_fixed_vuln":  po.IgnoreNotFixedVuln,
		"ignore_lang_vuln":       po.IgnoreLangVuln,
	}
	bys, err := json.Marshal(po.Envs)
	if err == nil {
		updater["envs"] = string(bys)
	} else {
		logging.GetLogger().Err(err).Msg("rejectPolicyToUpdater")
	}

	bys, err = json.Marshal(po.SensitiveFile)
	if err == nil {
		updater["sensitive_file"] = string(bys)
	} else {
		logging.GetLogger().Err(err).Msg("rejectPolicyToUpdater")
	}

	return updater
}

func GlobalRejectPolicyToUpdater(po model.GlobalRejectPolicy) map[string]interface{} {
	updater := map[string]interface{}{
		"cicd_enable":    po.CICDEnable,
		"k8s_enable":     po.K8sEnable,
		"online_monitor": po.OnlineMonitor,
		"mode":           po.Mode,
	}
	return updater
}

func registryToUpdater(reg model.Registry) map[string]interface{} {
	updater := map[string]interface{}{
		"name": reg.Name,
		// "reg_type":    reg.RegType, // 仓库类型 + 地址不可编辑
		// "url":    reg.Url,
		"scanner_instance": reg.ScannerInstance,
		"username":         reg.Username,
		"password":         reg.Password,
		"description":      reg.Description,
		"sync_interval":    reg.SyncInterval,
		"access_key":       reg.AccessKey,
		"access_secret":    reg.AccessSecret,
		"region_id":        reg.RegionID,
		"instance_id":      reg.InstanceID,
	}
	return updater
}

type ScannerList struct {
	List *list.List
	Lock sync.Mutex
}

type ScannerDbFunc struct {
	Value    func() error
	RetryNum int
}

func (l *ScannerList) ReUpdataDBPop() ScannerDbFunc {
	l.Lock.Lock()
	defer l.Lock.Unlock()
	f := l.List.Front()
	l.List.Remove(f)
	return f.Value.(ScannerDbFunc)
}

func (l *ScannerList) ReUpdataDBPush(s ScannerDbFunc) {
	l.Lock.Lock()
	defer l.Lock.Unlock()
	s.RetryNum++
	if s.RetryNum > 5 {
		logging.GetLogger().Error().Msg("ReUpdataDBPush has Retry 5 times")
	} else {
		l.List.PushBack(s)
	}
}

type ModeImageResponse []*model.ImageResponse

func (m ModeImageResponse) Len() int {
	return len(m)
}

func (m ModeImageResponse) Less(i, j int) bool {
	// 在线在前,离线在后
	if m[i].Online && !m[j].Online {
		return true
	} else if m[j].Online && !m[i].Online {
		return false
	}
	// 未扫描在前，其次扫描中
	if m[i].ScanStatus == consts.ImageNotScan && m[j].ScanStatus != consts.ImageNotScan {
		return true
	} else if m[j].ScanStatus == consts.ImageNotScan && m[i].ScanStatus != consts.ImageNotScan {
		return false
	} else if m[i].ScanStatus == consts.ImageScanInProgress && m[j].ScanStatus != consts.ImageScanInProgress {
		return true
	} else if m[j].ScanStatus == consts.ImageScanInProgress && m[i].ScanStatus != consts.ImageScanInProgress {
		return false
	}
	// 再排序扫描结束时间
	if m[i].CompleteTime > m[j].CompleteTime {
		return true
	} else if m[j].CompleteTime < m[i].CompleteTime {
		return false
	}
	// 最后按名字的字典序排序
	return m[i].FullRepoName < m[j].FullRepoName
}

func (m ModeImageResponse) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}

func InIntSlice(v int, vlue []int) bool {
	for i := range vlue {
		if v == vlue[i] {
			return true
		}
	}
	return false
}
func InStringSlice(v string, vlue []string) bool {
	for i := range vlue {
		if v == vlue[i] {
			return true
		}
	}
	return false
}
func InInt64Slice(v int64, vlue []int64) bool {
	for i := range vlue {
		if v == vlue[i] {
			return true
		}
	}
	return false
}

func MergeArtifact(src jobs.Artifact, dst jobs.Artifact) {
	for k, v := range src {
		dst[k] = v
	}
}

// MatchSuffix 匹配敏感文件的文件名
func MatchSuffix(pre, rule string) bool {
	if pre == "" {
		return false
	}
	split := strings.Split(pre, ".")
	rule = strings.Replace(rule, ".", "", 1)
	return split[len(split)-1] == rule
}

func ParseConfigEnv(env []string) []model.EnvKeyValue {
	var res []model.EnvKeyValue
	for _, v := range env {
		index := strings.Index(v, "=")
		if index == -1 {
			continue
		}
		tmpEnv := model.EnvKeyValue{}
		tmpEnv.Key = v[0:index]
		envLen := len(v)
		if index+1 < envLen {
			tmpEnv.Value = v[index+1:]
		}
		res = append(res, tmpEnv)
	}
	return res
}

func ParseSoftWare(softs []model.Software) string {
	if len(softs) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range softs {
		lit = append(lit, fmt.Sprintf("%s(%s)", softs[i].Name, softs[i].Version))
	}

	return strings.Join(lit, ",")
}

func ParseLicense(softs []model.LicenseInfo) string {
	if len(softs) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range softs {
		lit = append(lit, softs[i].Name)
	}

	return strings.Join(lit, ",")
}

type GroupImageVulns []store.GroupImageVuln

func (s GroupImageVulns) Count() int64 {
	var all int64
	for i := range s {
		all += s[i].Count
	}
	return all
}

func (s GroupImageVulns) GetMaxSeverityInt() string {
	var maxSeverity int64 = -1
	for i := range s {
		if s[i].SeverityInt > maxSeverity {
			maxSeverity = s[i].SeverityInt
		}
	}
	return model.GetSeverity(maxSeverity)
}

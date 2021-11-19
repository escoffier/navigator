package component

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/harborv1"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/harborv2"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/hwswr"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/jfrog"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
func generateUUId(img model.ImageList, msgType string, interval int) uint64 {
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
	}
)

func FilterVulnsFromScanImage(scanDetails []model.SingleScanDetail) []model.RespSingleVulnDetail {

	var result []model.RespSingleVulnDetail
	for _, v := range scanDetails {
		if len(v.Vulns) == 0 {
			continue
		}
		if lang, ok := LanguageMap[strings.ToLower(v.Type)]; ok {
			if lang != "GO" {
				for _, vuln := range v.Vulns {
					tmpRespSingle := model.RespSingleVulnDetail{}
					if strings.Contains(vuln.Trivy[0].PkgName, "struts2") && lang == "Java" {
						tmpRespSingle.Frame = "struts2"
					} else if strings.Contains(vuln.Trivy[0].PkgName, "fastjson") && lang == "Java" {
						tmpRespSingle.Frame = "fastjson"
					} else {
						tmpRespSingle.Language = lang
					}
					tmpRespSingle.TargetFileNmae = v.Target
					tmpRespSingle.NewVulnDetail = vuln
					result = append(result, tmpRespSingle)
				}
			} else {
				for _, vuln := range v.Vulns {
					tmpRespSingle := model.RespSingleVulnDetail{}
					index := strings.LastIndex(v.Target, "/")
					if index == -1 {
						tmpRespSingle.TargetFileNmae = "/"
						tmpRespSingle.Gobinary = v.Target
					} else {
						tmpRespSingle.TargetFileNmae = v.Target[0:index] // 文件路径
						tmpRespSingle.Gobinary = v.Target[index+1:]      // 文件名
					}
					tmpRespSingle.NewVulnDetail = vuln
					result = append(result, tmpRespSingle)
				}
			}
		} else {
			for _, vuln := range v.Vulns {
				tmpRespSingle := model.RespSingleVulnDetail{}
				tmpRespSingle.NewVulnDetail = vuln
				tmpRespSingle.TargetFileNmae = v.Target
				result = append(result, tmpRespSingle)
			}
		}
	}
	return result
}

func CalculateVulnScore(imascan model.ScanImage, cus map[string]model.RejectVuln) int {
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
	fileterScan := FilterVulnsFromScanImage(imascan.VulnInfo)
	ans := 50
	for _, vu := range fileterScan {
		if cu, ok := cus[vu.CVEID]; ok && cu.RejectPolicy == model.RejectPolicyIgnore {
			continue
		}
		if !exitScore[vu.Trivy[0].Severity] {
			ans = ans - subScore[vu.Trivy[0].Severity]
			exitScore[vu.Trivy[0].Severity] = true
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
func sendMsgToEventCenter(ctx context.Context, reqBody model.ReqBody) error {

	caCert, err := ioutil.ReadFile(consts.GRPC_CA_PATH)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "CICD open /auth/ca/tls.crr error ")
		return err
	}

	clientCertPool := x509.NewCertPool()
	if !clientCertPool.AppendCertsFromPEM(caCert) {
		return err
	}

	cert, err := tls.LoadX509KeyPair(consts.HTTPS_CLIENT_CERT_PATH, consts.HTTPS_CLIENT_PRIVATE_KEY)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "CICD LoadX509KeyPair/eventcenter-config/tls.crt error")
		return err
	}

	cli := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      clientCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	JSONBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	logging.GetLogger().Debug().Msg(fmt.Sprintf("send msg to event center：%s", string(JSONBytes)))

	host := consts.TENSORSEC_EVENTCENTER_SERVICE_HOST
	port := os.Getenv("EVENTCENTER_SERVICE_PORT_EVENTCENTER_HTTP")
	if port == "" {
		logging.GetLogger().Debug().Msgf("CICD event center port:%s", port)
		port = consts.TENSORSEC_EVENTCENTER_SERVICE_PORT
	}

	uri := fmt.Sprintf("%s:%s%s", host, port, consts.EventcenterURI)

	logging.GetLogger().Debug().Msgf("CICD event center URI:%s", uri)

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(JSONBytes))
	if err != nil {
		logging.GetLogger().WithContext(ctx).Infof("CICD send msg to event center http.NewRequest error :%s", err.Error())
		return err
	}

	rsp, err := cli.Do(req)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Infof("CICD get event center cli.Do(req) error :%s", err.Error())
		return err
	}
	defer rsp.Body.Close()
	body, _ := ioutil.ReadAll(rsp.Body)
	if rsp.StatusCode >= http.StatusMultipleChoices || rsp.StatusCode < http.StatusOK {
		logging.GetLogger().WithContext(ctx).Infof("CICD send msg to event centor, error message: %s", string(body))
		return errors.New(string(body))
	}
	return nil
}

func mergeRejectRecord(img model.ImageList, record []ReasonAndDetail) model.RejectRecord {
	res := model.RejectRecord{
		Library:      img.Library,
		FullRepoName: img.FullRepoName,
		Tag:          img.Tags,
		RejectAt:     time.Now().UTC(),
		Digest:       img.Digest, // 这里把digest存起来，好排查问题
	}

	reasonMap := make(map[int64]int64)
	reasonDetailMap := make(map[string]int64)
	reasons := make([]int64, 0)
	reasonDetails := make([]string, 0)

	for i := range record {
		if reasonMap[record[i].RejectReason] < 1 {
			reasons = append(reasons, record[i].RejectReason)
			reasonMap[record[i].RejectReason]++
		}

		if reasonDetailMap[record[i].RejectDetail] < 1 {
			reasonDetails = append(reasonDetails, record[i].RejectDetail)
			reasonDetailMap[record[i].RejectDetail]++
		}
		// 对同一个仓库来说，只会设置一个阻断评分和阻断级别,所以这里可以直接在循环中更新值
		if record[i].VulnScore > 0 {
			res.VulnScore = record[i].VulnScore
		}
		if record[i].VulnLevel != "" {
			res.VulnLevel = record[i].VulnLevel
		}
	}
	reasonsDuplication := make(map[string]string)
	for _, r := range reasons {
		reasonsDuplication[strconv.Itoa(int(r))] = strconv.Itoa(int(r))
	}
	if bys, err := json.Marshal(reasonsDuplication); err == nil {
		res.RejectReasonJson = bys
	}
	res.RejectDetail = strings.Join(reasonDetails, "|")
	return res
}

func getLayerString(img model.ImageList) string {
	if img.Layers != "" {
		return img.Layers
	}

	lays := make([]string, 0)
	// 先看v2
	for j := range img.ManifestV2.Layers {
		lays = append(lays, img.ManifestV2.Layers[j].Digest)
	}

	// 再看v1
	if len(lays) == 0 {
		for j := range img.ManifestV1.HistoryV1 {
			lays = append(lays, "sha256:"+img.ManifestV1.HistoryV1[j].LayerDegest)
		}
	}

	// 如果还是没有，就序列化试试
	if len(lays) == 0 && len(img.ManifestV2JSON) > 0 {
		maniFestv2 := new(model.ManifestV2)
		if err := json.Unmarshal(img.ManifestV2JSON, maniFestv2); err == nil {
			for j := range maniFestv2.Layers {
				lays = append(lays, maniFestv2.Layers[j].Digest)
			}
		}
	}

	// 再序列化v1
	if len(lays) == 0 && len(img.ManifestV1JSON) > 0 {
		maniFestV1 := new(model.ManifestV1)
		if err := json.Unmarshal(img.ManifestV1JSON, maniFestV1); err == nil {
			for _, his := range maniFestV1.History {
				for _, v := range his {
					hv1 := new(model.HistoryV1)
					if err := json.Unmarshal([]byte(v), hv1); err == nil {
						lays = append(lays, "sha256:"+hv1.LayerDegest)
					}
				}
			}
		}
	}
	return strings.Join(lays, "|")
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
		return errors.New("no Malicious policy")
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

	if po.WebShellScore > 10 || po.WebShellScore < 4 {
		return errors.New("webshell阻断分数设置不正确，可选选项包括4、5、6、7、8、9、10共7项")
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
	}
	bys, err := json.Marshal(po.Envs)
	if err == nil {
		updater["envs"] = string(bys)
	} else {
		logging.GetLogger().Error().Err(err).Msg("rejectPolicyToUpdater")
	}

	bys, err = json.Marshal(po.SensitiveFile)
	if err == nil {
		updater["sensitive_file"] = string(bys)
	} else {
		logging.GetLogger().Error().Err(err).Msg("rejectPolicyToUpdater")
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

func validateRegistry(reg model.Registry, valTY string) error {
	if reg.Name == "" {
		return errors.New("no name")
	}
	if reg.Username == "" {
		return errors.New("no username")
	}
	if reg.PasswordString == "" {
		return errors.New("no password")
	}
	if reg.SyncInterval < 0 {
		return errors.New("SyncInterval must than 0")
	}
	if valTY == consts.ValidateCreate {
		if reg.Url == "" && len([]rune(reg.Url)) > 255 {
			return errors.New("registry address is illegal")
		}
		if err := validateRegistryType(reg.RegType); err != nil {
			return err
		}
	}
	return nil
}

func validateRegistryType(regType string) error {
	if regType == "" || (regType != docker.Version && regType != harborv1.HarborVersion &&
		regType != harborv2.HarborVersion && regType != hwswr.Version && regType != jfrog.Version) {
		return errors.New("registry type is illegal")
	}
	return nil
}

func registryToUpdater(reg model.Registry) map[string]interface{} {
	updater := map[string]interface{}{
		"name": reg.Name,
		// "reg_type":    reg.RegType, // 仓库类型 + 地址不可编辑
		// "url":    reg.Url,
		"username":      reg.Username,
		"password":      reg.Password,
		"description":   reg.Description,
		"sync_interval": reg.SyncInterval,
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
	s.RetryNum += 1
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

func InInSlice(v int, vlue []int) bool {
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

func DeDuplicationInt64Slice(va []int64) []int64 {
	exit := make(map[int64]int64)
	ans := make([]int64, 0)
	for i := range va {
		if exit[va[i]] == 0 {
			ans = append(ans, va[i])
			exit[va[i]]++
		}
	}
	return ans
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

package imagesec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Webshell struct {
	ID          int64  `gorm:"primaryKey" json:"id"`
	UniqueID    uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	Filename    string `gorm:"column:filename" json:"filename"`
	Size        int64  `gorm:"column:size" json:"size"` // 单位：B
	MD5         string `gorm:"column:md5" json:"md5"`
	FileMod     string `gorm:"column:file_mod" json:"fileMod"` // drwxr-xr-x@ 28 liuqianli  staff
	Code        string `gorm:"column:code" json:"code"`
	RiskLevel   string `gorm:"column:risk_level" json:"riskLevel"`
	Description string `gorm:"column:description" json:"description"` // 描述。如php一句话木马
	Version     uint64 `gorm:"column:version" json:"version"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"`
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"`
}

type WebshellToImage struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	UniqueTarget  uint64 `gorm:"column:unique_target" json:"uniqueTarget,string"`
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	LayerDigest   string `gorm:"column:layer_digest" json:"layerDigest"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

type WebshellView struct {
	ID               int64          `json:"id"`
	UniqueID         uint64         `json:"uniqueID,string"`
	Filename         string         `json:"filename"`
	Filepath         string         `json:"filepath"`
	FileType         string         `json:"filetype"`
	Size             string         `json:"size"`
	MD5              string         `json:"md5"`
	Mod              Mod            `json:"mod"`
	Code             []WebshellCode `json:"code"`
	CodeJSON         string         `json:"-"` // 原数据
	RiskLevel        string         `json:"riskLevel"`
	Description      string         `json:"description"` // 描述。如php一句话木马
	RiskDetail       string         `json:"riskDetail"`
	Recommend        string         `json:"recommend"`
	Version          uint64         `json:"version"`
	DownloadFilename string         `json:"downloadFilename"`
	CreatedAt        int64          `json:"createdAt"`
	UpdatedAt        int64          `json:"updatedAt"`

	PolicyDetect PolicyDetect `json:"policyDetect"` // 对各个策略的检测结果
}

func (vi *WebshellView) CodeContent() string {
	if bys, err := json.Marshal(vi.Code); err == nil {
		return string(bys)
	}
	return ""
}

func (vi *WebshellView) GenFullFilename() string {
	return vi.Filepath + vi.Filename
}

func (vi *WebshellView) GenDownloadFilename() string {

	split := strings.Split(vi.Filename, ".")
	if len(split) > 0 && split[0] != "" {
		df := split[0] + ".zip"
		vi.DownloadFilename = df
		return df
	}
	return ""
}

type WebshellContent struct {
	Line    string   `json:"line"`
	Problem []string `json:"problem"`
}

type Mod struct {
	User  string `json:"user"`
	Group string `json:"group"`
	Perm  string `json:"perm"`
}

func (vi *Webshell) Serialize() {
	vi.RiskLevel = strings.ToLower(vi.RiskLevel)
}

func (vi *Webshell) ToWebshellView() *WebshellView {
	after := WebshellView{
		ID:          vi.ID,
		UniqueID:    vi.UniqueID,
		Filename:    vi.Filename,
		Version:     vi.Version,
		MD5:         vi.MD5,
		Code:        make([]WebshellCode, 0),
		RiskLevel:   strings.ToLower(vi.RiskLevel),
		Description: vi.Description,
		CreatedAt:   vi.CreatedAt,
		UpdatedAt:   vi.UpdatedAt,
	}

	split := strings.Split(vi.Filename, "/")
	if len(split) > 1 {
		after.Filename = split[len(split)-1]
		after.Filepath = strings.Join(split[:len(split)-1], "/")
	}

	if after.Filepath != "" {
		after.Filepath = after.Filepath + "/"
	}

	split3 := strings.Split(vi.Filename, ".")
	if len(split3) >= 2 {
		after.FileType = split3[len(split3)-1]
	}

	split2 := strings.Split(vi.FileMod, " ")
	// sample: drwxr-xr-x@ liuqianli  staff
	if len(split2) >= 3 {
		after.Mod.Perm = split2[0]
		after.Mod.User = split2[1]
		after.Mod.Group = split2[2]
	}

	hm := make([]hMWebshellCode, 0)
	if vi.Code != "" {
		if err := json.Unmarshal([]byte(vi.Code), &hm); err != nil {
			logging.Get().Err(err).Msg("parse webshell code")
			hm = make([]hMWebshellCode, 0)
		}
	}
	for i := range hm {
		af := WebshellCode{
			Name:   hm[i].Name,
			Offset: hm[i].Offset,
			Data:   ParseWebshellCode(hm[i].Data),
			LineNo: hm[i].LineNo,
		}
		af.Parsed = af.Data != hm[i].Data
		after.Code = append(after.Code, af)
	}

	sort.Sort(WebshellCodes(after.Code))
	after.Size = util.ParseByteSize(vi.Size)
	split4 := strings.Split(vi.Description, "-")
	if len(split4) > 0 {
		after.RiskDetail = split4[0]
	}
	if len(split4) > 1 {
		after.Recommend = split4[1]
	}
	if after.Recommend == "" {
		after.Recommend = "建议清理"
	}
	if after.RiskDetail == "" {
		after.RiskDetail = "webshell"
	}

	if after.Filepath == "" {
		after.Filepath = "/"
	}
	if !strings.HasPrefix(after.Filepath, "/") {
		after.Filepath = "/" + after.Filepath
	}
	if !strings.HasSuffix(after.Filepath, "/") {
		after.Filepath = after.Filepath + "/"
	}

	after.DownloadFilename = after.GenDownloadFilename()

	return &after
}

func (vi *WebshellView) AdaptI18(ctx context.Context) {
	lang, ok := ctx.Value(AcceptLanguage).(string)
	if ok && lang == "en" {
		vi.RiskDetail = WebshellRiskEN(strings.TrimSpace(vi.RiskDetail))
		vi.Recommend = WebshellRecommendEN(strings.TrimSpace(vi.Recommend))
	}

}

func (vi *Webshell) Deserialize() {

}

func ParseWebshellCode(pre string) string {
	if strings.Contains(pre, HMWebshellSalt) {
		return pre
	}
	after, err := base64.StdEncoding.DecodeString(pre)
	if err != nil {
		return pre
	}
	return string(after)
}

func (vi *Webshell) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.Filename == "" {
		return fmt.Errorf("not get Filename")
	}
	// if vi.MD5 == "" {
	// 	return fmt.Errorf("not get md5")
	// }
	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	return nil
}

// 盒马 webshell 扫描的原始数据解析
type hMWebshellCode struct {
	Name   string `json:"Name"`
	Offset int64  `json:"Offset"`
	Data   string `json:"Data"`
	LineNo int64  `json:"line_no"`
}

type WebshellCode struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"` // 注意，河马把 \n 也算了的,且是从文件头第一个字符起算，不是以该行起算
	Data   string `json:"data"`
	LineNo int64  `json:"lineNo"` // 扫描结果都是0，可以认为这个字段已废弃
	Parsed bool   `json:"parsed"` // 河马加密，是否能解析，不能解析的数据不能返回给前端
}

type WebshellCodes []WebshellCode

func (vi WebshellCodes) Len() int {
	return len(vi)
}

func (vi WebshellCodes) Less(i, j int) bool {
	return vi[i].Offset < vi[j].Offset
}

func (vi WebshellCodes) Swap(i, j int) {
	vi[i], vi[j] = vi[j], vi[i]
}

func (vi *Webshell) Same(after *Webshell) bool {
	vi.UniqueID = vi.GenUniqueID()
	after.UniqueID = after.GenUniqueID()
	return vi.UniqueID == after.UniqueID
}

func (vi *Webshell) GenUniqueID() uint64 {
	key := fmt.Sprintf(UniqueWebshellFormat, vi.MD5, vi.Filename)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *Webshell) TableName() string {
	return "ivan_scan_image_webshell"
}

func (vi *WebshellToImage) GenUniqueID() uint64 {
	key := fmt.Sprintf("%d-%d-%s", vi.ImageUniqueID, vi.UniqueTarget, vi.LayerDigest)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *WebshellToImage) Same(after *WebshellToImage) bool {
	if vi.LayerDigest != after.LayerDigest || vi.ImageUniqueID != after.ImageUniqueID ||
		vi.UniqueTarget != after.UniqueTarget {
		return false
	}
	return true
}

func (vi *WebshellToImage) TableName() string {
	if vi == nil {
		return ""
	}
	return "ivan_image_webshell_issue"
}

// 为啥要写两份呢，因为会循环引用，
var riskDetail map[string]string
var recommend map[string]string

func WebshellRiskEN(det string) string {
	if riskDetail == nil {
		riskDetail =
			map[string]string{
				"asp webshell":         "asp webshell",
				"PHP后门":                "PHP backdoor",
				"ASP后门":                "ASP backdoor",
				"php webshell":         "php webshell",
				"ASP一句话后门":             "ASP backdoor",
				"JFoler9 jsp webshell": "JFoler9 jsp webshell",
				"DDOS类PHP攻击后门":         "DDOS attack backdoor",
				"JSP小马":                "JSP Trojan",
				"JSPSPY JSP大马":         "JSP Trojan",
				"PHP上传后门":              "PHP backdoor",
				"图片型PHP后门":             "PHP backdoor",
				"JSP Caidao":           "JSP Caidao",
				"JFolder jsp webshell": "JFolder jsp webshell",
				"ASP小马":                "JSP Trojan",
				"变形PHP一句话后门":           "PHP backdoor",
				"危险的PHP反序列化操作":         "PHP deserialization operation",
				"JSP后门":                "JSP backdoor",
				"JSP可疑文件":              "JSP Suspicious file",
				"weevely PHP后门":        "weevely PHP backdoor",
				"jsp webshell":         "jsp webshell",
				"C99SHELL PHP大马":       "C99SHELL PHP Trojan",
				"ASP加密脚本":              "ASP encryption script",
				"PHP变量函数后门代码":          "PHP variable function backdoor code",
				"jshell JSP大马":         "jshell JSP Trojan",
				"ASP大马":                "JSP Trojan",
				"aspx webshell":        "aspx webshell",
				"PHP大马":                "PHP Trojan",
				"命令执行ASP后门":            "Command Execution ASP Backdoor",
				"可疑的PHP一句话":            "Suspicious PHP word",
				"pwn jsp webshell":     "pwn jsp webshell",
				"植入类PHP后门":             "Implanting a PHP-like backdoor",
				"jspx webshell":        "jspx webshell",
				"ghost PHP大马":          "ghost PHP Trojan",
				"PHP一句话后门":             "PHP backdoor",
				"odd PHP后门":            "odd PHP backdoor",
				"K81 JSP后门":            "K81 JSP backdoor",
				"cmd PHP小马":            "cmd PHP Trojan",
				"dodoziph PHP后门":       "dodoziph PHP backdoor",
				"cnseay PHP一句话后门":      "cnseay PHP backdoor",
				"PHP IIS SPY":          "PHP IIS SPY",
				"webshell":             "webshell",
				"PHP异常包含":              "PHP exception contains",
				"变形ASP一句话后门":           "JSP backdoor",
				"PHP小马":                "PHP Trojan",
				"Ani PHP小马":            "PHP Trojan",
				"EFSO ASP后门":           "JSP backdoor",
				"K8 JSP小马":             "JSP Trojan",
				"寄生虫SEO类PHP后门":         "PHP backdoor",
				"catches PHP后门":        "PHP backdoor",
				"ntdaddy ASP后门":        "ASP backdoor",
				"404 ASP后门":            "ASP backdoor",
				"海洋顶端ASP大马":            "JSP Trojan",
				"菜刀ASP一句话后门":           "JSP backdoor",
				"菜刀PHP一句话后门":           "JSP backdoor",
				"疑似PHP后门":              "PHP backdoor",
				"疑似ASP后门":              "PHP backdoor",
				"PHP加密文件":              "PHP encrypted file",
				"pl webshell":          "pl webshell",
				"冰蝎3.0 PHP":            "PHP Trojan",
				"Godzilla JSP":         "Godzilla JSP",
				"Godzilla ASPX":        "Godzilla ASPX",
				"冰蝎3.0 ASPX":           "jspx webshell",
				"冰蝎3.0 JSP":            "JSP Trojan",
				"Godzilla PHP":         "Godzilla PHP",
				"冰蝎3.0 asp":            "JSP Trojan",
			}
	}
	des := riskDetail[det]
	if des == "" {
		return "webshell"
	}

	return des
}

func WebshellRecommendEN(rec string) string {
	if recommend == nil {
		recommend = map[string]string{
			"建议清理":            "recommend clean",
			"建议人工确认":          "recommend manual verification",
			"建议进行人工确认":        "recommend manual verification",
			"具有执行命令的操作，请检查文件": "has an action to execute the command, check the file",
			"检查确认后删除相关代码":     "Delete the relevant code after checking and confirming",
			"$$利用方式2":         "recommend clean",
			"建议删除":            "recommend clean",
			"JSP后门，建议清理":      "recommend clean",
			"ASPX后门，建议清理":     "recommend clean",
			"PHP后门，建议清理":      "recommend clean",
			"asp后门，建议清理":      "recommend clean",
			"建议人工鉴定":          "recommend manual verification",
		}
	}
	ans := recommend[rec]
	if ans == "" {
		ans = "recommend clean"
	}
	return ans
}

type CertainWebshell struct {
	ID            int64  `json:"id" gorm:"column:id"`
	Size          int64  `json:"size" gorm:"column:size"`
	Filepath      string `json:"filepath" gorm:"column:filepath;type:text"`
	Md5Hash       string `json:"md5Hash" gorm:"column:md5hash;type:text"`
	Description   string `json:"description" gorm:"column:description;type:text"`
	MaliciousData string `json:"maliciousData" gorm:"column:malicious_data;type:text"`
}

func (CertainWebshell) TableName() string {
	return "tbl_b"
}

type MaybeWebshell struct {
	ID            int64  `json:"id" gorm:"column:id"`
	Size          int64  `json:"size" gorm:"column:size"`
	Filepath      string `json:"filepath" gorm:"column:filepath;type:text"`
	Md5Hash       string `json:"md5Hash" gorm:"column:md5hash;type:text"`
	Description   string `json:"description" gorm:"column:description;type:text"`
	MaliciousData string `json:"maliciousData" gorm:"column:malicious_data;type:text"`
}

func (MaybeWebshell) TableName() string {
	return "tbl_s"
}

type WebshellKafkaInfo struct {
	FileMd5  string `json:"fileMd5"`
	Data     []byte `json:"data"`
	Filename string `json:"filename"`
}

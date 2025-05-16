package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"os"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// VulnInfo 结构体用于解析漏洞信息
type VulnInfo struct {
	CVSS             map[string]CVSS `json:"CVSS"`
	Description      string          `json:"Description"`
	References       []string        `json:"References"`
	Severity         string          `json:"Severity"`
	Title            string          `json:"Title"`
	LastModifiedDate string          `json:"LastModifiedDate"`
	PublishedDate    string          `json:"PublishedDate"`
	CweIDs           []string        `json:"CweIDs"`
}

type CVSS struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

func GetCvss(v *VulnInfo) CVSS {
	if c, ok := v.CVSS["nvd"]; ok {
		return c
	}
	for _, c := range v.CVSS {
		return c
	}
	return CVSS{}
}

// Config 应用配置
type Config struct {
	DBPath     string
	OutputPath string
}

// BoltReader 处理BoltDB读取的结构体
type BoltReader struct {
	config Config
	db     *bolt.DB
	logger *scannerUtils.LogEvent
}

// NewBoltReader 创建新的BoltReader实例
func NewBoltReader(config Config) *BoltReader {
	return &BoltReader{
		config: config,
		logger: scannerUtils.NewLogEvent(scannerUtils.WithModule("ReadBolt")),
	}
}

// Open 打开BoltDB数据库
func (r *BoltReader) Open() error {
	options := bolt.Options{
		Timeout:  time.Second * 15,
		ReadOnly: true,
	}

	db, err := bolt.Open(r.config.DBPath, 0600, &options)
	if err != nil {
		return err
	}
	r.db = db
	return nil
}

// Close 关闭数据库连接
func (r *BoltReader) Close() {
	if r.db != nil {
		r.db.Close()
	}
}

// ExportToCSV 将漏洞数据导出到CSV
func (r *BoltReader) ExportToCSV() error {
	// 创建CSV文件
	csvFile, err := os.Create(r.config.OutputPath)
	if err != nil {
		return err
	}
	defer csvFile.Close()

	// 创建CSV写入器
	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// 写入CSV头部
	headers := []string{
		"VulnID",
		"Title",
		"Severity",
		"CVSS Score",
		"CVSS Vector",
		// "Description",
		// "References",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 读取漏洞数据
	count := 0
	err = r.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("vulnerability"))
		if bucket == nil {
			return ErrBucketNotFound
		}

		return bucket.ForEach(func(k, v []byte) error {
			vulnID := string(k)

			// 解析漏洞信息
			var vulnInfo VulnInfo
			if err := json.Unmarshal(v, &vulnInfo); err != nil {
				r.logger.Info().Str("vulnID", vulnID).Err(err).Msg("解析漏洞数据失败")
				return nil // 继续处理下一个
			}

			// 将引用列表转换为单个字符串
			// references := joinReferences(vulnInfo.References)

			// 写入CSV行
			row := []string{
				vulnID,
				vulnInfo.Title,
				vulnInfo.Severity,
				strconv.FormatFloat(GetCvss(&vulnInfo).V3Score, 'f', 1, 64),
				GetCvss(&vulnInfo).V3Vector,
				// vulnInfo.Description,
				// references,
			}

			if err := writer.Write(row); err != nil {
				r.logger.Info().Str("vulnID", vulnID).Err(err).Msg("写入CSV失败")
				return nil // 继续处理下一个
			}

			count++
			if count%100 == 0 {
				r.logger.Info().Int("count", count).Msg("处理进度")
			}

			return nil
		})
	})

	if err != nil {
		return err
	}

	r.logger.Info().Int("total", count).Str("output", r.config.OutputPath).Msg("导出完成")
	return nil
}

// 自定义错误
var ErrBucketNotFound = &customError{"未找到vulnerability bucket"}

type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}

// joinReferences 将引用列表连接为分号分隔的字符串
func joinReferences(refs []string) string {
	if len(refs) == 0 {
		return ""
	}

	result := refs[0]
	for i := 1; i < len(refs); i++ {
		result += "; " + refs[i]
	}
	return result
}

func main() {
	// 定义命令行参数
	config := Config{}
	flag.StringVar(&config.DBPath, "db", "/Users/liuqianli/Downloads/trivy.db", "BoltDB文件路径")
	flag.StringVar(&config.OutputPath, "output", "vulnerabilities2.csv", "输出CSV文件路径")
	flag.Parse()

	logger := logging.GetLogger()

	if config.DBPath == "" {
		logger.Fatal().Msg("请提供BoltDB文件路径，使用 -db 参数")
	}

	// 创建并使用BoltReader
	reader := NewBoltReader(config)
	if err := reader.Open(); err != nil {
		logger.Fatal().Err(err).Msg("打开BoltDB失败")
	}
	defer reader.Close()

	if err := reader.ExportToCSV(); err != nil {
		logger.Fatal().Err(err).Msg("导出CSV失败")
	}
}

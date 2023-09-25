package component

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/mq"

	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SecretPattern struct {
	DescriptionEn string `json:"descriptionEn"`
	DescriptionZh string `json:"descriptionZh"`
	Type          string `json:"secret_type"`
	Value         string `json:"value"`
}

type SensitiveDescription struct {
	En string `json:"en"`
	Zh string `json:"zh"`
}

var (
	GlobalSensitiveFilenameRegExpMap map[*regexp.Regexp]*SensitiveDescription
	GlobalSensitiveFilenameRegExp    *regexp.Regexp
)

func init() {
	GlobalSensitiveFilenameRegExpMap = make(map[*regexp.Regexp]*SensitiveDescription)
	secretPatterns := []SecretPattern{}
	s := SensitiveScan{}
	if err := s.readJSONFile(filepath.Join("/configs", "scanner", "patterns.json"), &secretPatterns); err != nil {
		return
	}

	var sensitiveFilenameRegExpStrList []string
	for _, item := range secretPatterns {
		if item.Type == "Filename" {
			GlobalSensitiveFilenameRegExpMap[regexp.MustCompile(item.Value)] = &SensitiveDescription{
				En: item.DescriptionEn,
				Zh: item.DescriptionZh,
			}
			sensitiveFilenameRegExpStrList = append(sensitiveFilenameRegExpStrList, item.Value)
		}
	}
	GlobalSensitiveFilenameRegExp = regexp.MustCompile(strings.Join(sensitiveFilenameRegExpStrList, "|"))

}

type SensitiveScan struct {
	SensitiveFilenameRegExpMap map[*regexp.Regexp]*SensitiveDescription
	PasswordFileExt            []string
	SensitiveFilenameRegExp    *regexp.Regexp
	PasswordFileContentRegExp  *regexp.Regexp
	Passwd                     []string
	MqWriter                   mq.Writer
}

func (s *SensitiveScan) SendKafka(saveInfo scannermodel.WebshellSaveInfo) error {
	// if len(saveInfo.Data) == 0 {
	// 	logging.Get().Error().Msg("SensitiveScan file data is empty")
	// 	return nil
	// }
	bys, err := json.Marshal(saveInfo)
	if err != nil {
		return err
	}

	err = s.MqWriter.Write(context.Background(), scannermodel.WebshellKafkaTopic, kafka.Message{
		Key:   []byte(scannermodel.WebshellKafkaKey),
		Value: bys,
	})
	if err != nil {
		logging.Get().Err(err).Str("Filename", saveInfo.Filename).Str("FileMd5", saveInfo.FileMd5).Msg("SensitiveScan SendKafka")
		return err
	}
	logging.Get().Debug().Int("Data", len(saveInfo.Data)).Str("FileMd5", saveInfo.FileMd5).Msg("SensitiveScan SendKafka")
	return nil
}

func (s *SensitiveScan) FindSensitiveFileNamesInImage(tarFileName string) ([]model.Sensitive, error) {
	sensitiveFiles := make([]model.Sensitive, 0)

	tarFile, err := os.Open(tarFileName)
	if err != nil {
		return sensitiveFiles, fmt.Errorf("Failed to open %s: %w", tarFileName, err)
	}
	defer tarFile.Close()

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return sensitiveFiles, fmt.Errorf("Failed to create dockerarchive decompressed stream: %w", err)
	}
	defer decompressStreamReader.Close()

	tarReader := tar.NewReader(decompressStreamReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return sensitiveFiles, fmt.Errorf("Failed to advance tarReader: %w", err)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		}
		isSensitiveFile := false
		filename := header.Name
		fileByte, err := io.ReadAll(tarReader)

		if err != nil {
			logging.Get().Err(err).Msgf("copy from tarReader error")
			continue
		}
		if len(fileByte) == 0 {
			continue
		}
		for re := range s.SensitiveFilenameRegExpMap {
			if re.FindString(filename) != "" {
				isSensitiveFile = true
				break
			}
		}

		if util.ExistInStringSlice(s.PasswordFileExt, filepath.Ext(filename)) {
			logging.Get().Debug().Str("filename", filename).Msg("find passwd file")

			// 如果是配置文件，读取文件内容
			scanner := bufio.NewScanner(bytes.NewReader(fileByte))
			for scanner.Scan() {
				line := scanner.Text()
				passwd := s.HasWeakPassword(line)
				if passwd {
					isSensitiveFile = true
					break
				}
			}
		}
		if isSensitiveFile {
			fileMd5, err := s.FileMD5(bytes.NewReader(fileByte))
			if err != nil {
				logging.Get().Err(err).Msgf("FileMD5")
				continue
			}
			saveInfo := scannermodel.WebshellSaveInfo{
				FileMd5: fileMd5,
				Data:    fileByte,
			}

			if err := s.SendKafka(saveInfo); err != nil {
				logging.Get().Debug().Str("file", header.Name).Msg("FindSensitiveFile send kafka failed")
				continue
			}
			logging.Get().Debug().Str("file", header.Name).Str("md5", fileMd5).Msg("FindSensitiveFile")

			sensitiveFiles = append(sensitiveFiles, model.Sensitive{
				// 暂时没有获取敏感文件的描述，后期优化扫描器时获取
				Name: header.Name,
				Md5:  fileMd5,
			})
		}
	}
	return sensitiveFiles, nil
}

func (s *SensitiveScan) enrichSensitiveFilesWithDescriptions(sensitiveFiles []string, sensitiveMd5 map[string]string) []model.Sensitive {
	imageSensitiveFiles := make([]model.Sensitive, 0)
	for _, f := range sensitiveFiles {
		for re, description := range s.SensitiveFilenameRegExpMap {
			//
			// You may ask - why are we applying regex twice?
			// 1. here: r.sensitiveFilenameRegExp.FindString(header.Name)
			// 2. and here, r.sensitiveFilenameRegExpMap, below this comment?
			//
			// I'm glad you ask.
			//
			// sensitiveFilenameRegExp is a single regex state machine that checks
			// for all possible sensitive filenames. In principle, it should be faster
			// than iterating over single-filename regexes.
			// So we use it to find sensitive filenames in the first place.
			//
			// Then we use sensitiveFilenameRegExpMap here, to add descriptions.
			//
			// Is it faster? Is it less memory intensive?
			// I don't know. We may want to check whether we actually need two
			// regex passes like this.
			// My suspicion is that we don't need two passes.
			// But I'm going to leave it as it is right now, as I don't think
			// it's very important.
			//
			if re.MatchString(f) {
				logging.Get().Debug().Str("file", f).Str("description", description.En).Msg("FindSensitiveFile")

				imageSensitiveFiles = append(imageSensitiveFiles, model.Sensitive{
					Name:          f,
					DescriptionEn: description.En,
					DescriptionZh: description.Zh,
					Md5:           sensitiveMd5[f],
				})
			}
		}
	}
	return imageSensitiveFiles
}

func (s *SensitiveScan) InitConfigFiles(filename string) error {
	if filename == filepath.Join("/configs", "scanner", "patterns.json") {
		s.SensitiveFilenameRegExpMap = GlobalSensitiveFilenameRegExpMap
		s.SensitiveFilenameRegExp = GlobalSensitiveFilenameRegExp
	}

	s.SensitiveFilenameRegExpMap = make(map[*regexp.Regexp]*SensitiveDescription)
	secretPatterns := []SecretPattern{}
	if err := s.readJSONFile(filename, &secretPatterns); err != nil {
		return err
	}

	var sensitiveFilenameRegExpStrList []string
	for _, item := range secretPatterns {
		if item.Type == "Filename" {
			s.SensitiveFilenameRegExpMap[regexp.MustCompile(item.Value)] = &SensitiveDescription{
				En: item.DescriptionEn,
				Zh: item.DescriptionZh,
			}
			sensitiveFilenameRegExpStrList = append(sensitiveFilenameRegExpStrList, item.Value)
		}
	}
	s.PasswordFileExt = []string{".conf", ".yml", ".ini", ".env", ".properties", ".cfg", ".toml"}
	s.SensitiveFilenameRegExp = regexp.MustCompile(strings.Join(sensitiveFilenameRegExpStrList, "|"))
	s.Passwd = []string{"password", "passwd", "PASSWORD", "PASSWD"}

	return nil
}

func (s *SensitiveScan) InitCustomConfig(jsonstr string) error {
	s.SensitiveFilenameRegExpMap = make(map[*regexp.Regexp]*SensitiveDescription)
	secretPatterns := []SecretPattern{}
	if err := json.Unmarshal([]byte(jsonstr), &secretPatterns); err != nil {
		return err
	}

	var sensitiveFilenameRegExpStrList []string
	for _, item := range secretPatterns {
		if item.Type == "Filename" {
			s.SensitiveFilenameRegExpMap[regexp.MustCompile(item.Value)] = &SensitiveDescription{
				En: item.DescriptionEn,
				Zh: item.DescriptionZh,
			}
			sensitiveFilenameRegExpStrList = append(sensitiveFilenameRegExpStrList, item.Value)
		}
	}
	s.SensitiveFilenameRegExp = regexp.MustCompile(strings.Join(sensitiveFilenameRegExpStrList, "|"))
	return nil
}

func (s *SensitiveScan) readJSONFile(path string, fieldPtr interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Failed to open file %s: %w", path, err)
	}
	defer f.Close()

	byteValue, _ := ioutil.ReadAll(f)
	err = json.Unmarshal(byteValue, fieldPtr)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal file %s: %w", path, err)
	}
	return nil
}

func (s *SensitiveScan) AddCustomConfig(rules []string) error {
	for i := range rules {
		comp, err := regexp.Compile(rules[i])
		if err != nil {
			logging.Get().Err(err).Str("senstiveRule", rules[i]).Msg("AddCustomConfig")
			continue
		}
		s.SensitiveFilenameRegExpMap[comp] = &SensitiveDescription{}
	}
	return nil
}

func (s *SensitiveScan) FileMD5(tar io.Reader) (string, error) {
	hash := md5.New()
	_, _ = io.Copy(hash, tar)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *SensitiveScan) HasWeakPassword(line string) bool {
	for i := range s.Passwd {
		if strings.HasPrefix(line, s.Passwd[i]) {
			pss := strings.Replace(line, s.Passwd[i], "", 1)
			pss = strings.TrimSpace(pss)
			if strings.HasPrefix(pss, "=") {
				pss = strings.Replace(pss, "=", "", 1)
				pss = strings.TrimSpace(pss)
			}
			if strings.HasPrefix(pss, ":") {
				pss = strings.Replace(pss, ":", "", 1)
				pss = strings.TrimSpace(pss)
			}
			if s.isWeakPassword(pss) {
				return true
			}
		}
	}
	return false
}

func (s *SensitiveScan) isWeakPassword(password string) bool {
	pattern := `^[a-zA-Z0-9]+$`
	match2, _ := regexp.MatchString(pattern, password)
	return match2
}

package component

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
	SensitiveFilenameRegExp    *regexp.Regexp
}

func (s *SensitiveScan) FindSensitiveFileNamesInImage(tarFileName string, sensitiveRegExp *regexp.Regexp) ([]model.Sensitive, error) {
	sensitiveFiles := []model.Sensitive{}

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
	sensitiveFilenames := []string{}
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
		if s.SensitiveFilenameRegExp.FindString(header.Name) != "" {
			logging.Get().Debug().Str("file", header.Name).Msg("FindSensitiveFile")
			if err == nil {
				sensitiveFilenames = append(sensitiveFilenames, header.Name)
			}
		}
	}

	enrichedSensitiveFiles := s.enrichSensitiveFilesWithDescriptions(sensitiveFilenames)
	return enrichedSensitiveFiles, nil
}

func (s *SensitiveScan) enrichSensitiveFilesWithDescriptions(sensitiveFiles []string) []model.Sensitive {
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
	s.SensitiveFilenameRegExp = regexp.MustCompile(strings.Join(sensitiveFilenameRegExpStrList, "|"))
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

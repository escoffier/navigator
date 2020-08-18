package redclair

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	dockerarchive "github.com/docker/docker/pkg/archive"

	"gopkg.in/yaml.v2"
)

// FileSignature ...
type FileSignature struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	HeadContent []byte `json:"head_content"`
}

// GetImageFileHash ...
func GetImageFileHash(file *tar.Reader, fileHeadSize int) (FileSignature, error) {
	var err error
	var content, headContent []byte
	if content, err = ioutil.ReadAll(file); err != nil {
		return FileSignature{}, err
	}
	fileHash := sha256.New()
	if len(content) >= fileHeadSize && fileHeadSize >= 0 {
		headContent = content[0:fileHeadSize]
	} else {
		headContent = content
	}
	if _, err = io.Copy(fileHash, bytes.NewReader(content)); err != nil {
		return FileSignature{}, err
	}
	fileHashByte := fileHash.Sum(nil)
	fileHashDigest := hex.EncodeToString(fileHashByte)
	return FileSignature{
		Digest:      fileHashDigest,
		HeadContent: headContent,
	}, nil
}

// GenerateTarHash ...
func GenerateTarHash(
	tarFileName string,
	maxSize int64,
	fileHeadSize int,
	ignoreRegExp *regexp.Regexp,
	softwareRegExp *regexp.Regexp,
) ([]FileSignature, []FileSignature, error) {
	// Only return file of 0 < size < [maxSize]
	// Filename should not matched with [ignoreRegExp], it is a list
	// Head [fileHeadSize] bytes of file will return
	// fileHeadSize = 0 means return no head content
	// fileHeadSize = -1 means return ALL content of file,
	// it is VERY HEAVY for memory but NOT heavy for efficiency

	rawFileReader, err := os.Open(tarFileName)
	if err != nil {
		return []FileSignature{}, []FileSignature{}, err
	}
	if rawFileReader == nil {
		return []FileSignature{}, []FileSignature{}, err
	}
	fileReader, err := dockerarchive.DecompressStream(rawFileReader)
	if err != nil {
		return []FileSignature{}, []FileSignature{}, err
	}
	if fileReader == nil {
		return []FileSignature{}, []FileSignature{}, err
	}
	tarReader := tar.NewReader(fileReader)
	var result []FileSignature
	var softwareFiles []FileSignature
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return []FileSignature{}, []FileSignature{}, err
		}
		if softwareRegExp.FindString(header.Name) != "" {
			fileSignature, err := GetImageFileHash(tarReader, -1)
			fileSignature.Name = header.Name
			fileSignature.Size = header.Size
			if err == nil {
				softwareFiles = append(softwareFiles, fileSignature)
			}
		}
		if header.Typeflag == tar.TypeReg &&
			0 < header.Size && header.Size <= maxSize &&
			ignoreRegExp.Find([]byte(header.Name)) == nil {
			fileSignature, err := GetImageFileHash(tarReader, fileHeadSize)
			fileSignature.Name = header.Name
			fileSignature.Size = header.Size
			if err == nil {
				result = append(result, fileSignature)
			}
		}
	}
	return result, softwareFiles, nil
}

// DistinctFileHash ...
func DistinctFileHash(src []FileSignature) (ret []FileSignature) {
	var result []FileSignature
	var hashSet = make(map[string]struct{})
	for _, v := range src {
		if _, exist := hashSet[v.Digest]; !exist {
			result = append(result, v)
			hashSet[v.Digest] = struct{}{}
		}
	}
	return result
}

// QuickRequest ...
func QuickRequest(
	method string,
	url string,
	reqHeader map[string]string,
	byteBody []byte,
	prettyJSON bool,
) (code int, result []byte, resHeader http.Header, reqErr error) {
	var requestBody io.Reader
	if byteBody != nil {
		requestBody = bytes.NewBuffer(byteBody)
	} else {
		requestBody = nil
	}
	req, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		return -1, []byte{}, nil, err
	}
	for k, v := range reqHeader {
		req.Header.Add(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, []byte{}, nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			fmt.Printf("%v", err)
			reqErr = err
		}
	}()
	result, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, []byte{}, res.Header, err
	}
	var resultPretty bytes.Buffer
	if !prettyJSON {
		return res.StatusCode, result, res.Header, nil
	}
	err = json.Indent(&resultPretty, result, "", "\t")
	if err != nil {
		return res.StatusCode, resultPretty.Bytes(), res.Header, nil
	}
	return res.StatusCode, result, res.Header, nil
}

const (
	// InfoColor ...
	InfoColor = "\033[1;34m%s\033[0m"
	// NoticeColor ...
	NoticeColor = "\033[1;36m%s\033[0m"
	// WarningColor ...
	WarningColor = "\033[1;33m%s\033[0m"
	// ErrorColor ...
	ErrorColor = "\033[1;31m%s\033[0m"
	// DebugColor ...
	DebugColor = "\033[0;36m%s\033[0m"
)

// SeverityMap Exported var used as mapping on CVE severity name to implied ranking
var SeverityMap = map[string]int{
	"Defcon1":    1,
	"Critical":   2,
	"High":       3,
	"Medium":     4,
	"Low":        5,
	"Negligible": 6,
	"Unknown":    7,
}

// ListenForSignal listens for interactions and executes the desired code when it happens
func ListenForSignal(fn func(os.Signal)) {
	signalChannel := make(chan os.Signal, 1)

	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGQUIT)
	for {
		execute := <-signalChannel
		fn(execute)
	}
}

// CreateTmpPath creates a temporary folder with a prefix
func CreateTmpPath(tmpPrefix string) string {
	tmpPath, err := ioutil.TempDir("", tmpPrefix)
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not create temporary folder: %s", err)
	}
	return tmpPath
}

// ParseWhitelistFile reads the Whitelist file and parses it
func ParseWhitelistFile(whitelistFile string) VulnerabilitiesWhitelist {
	whitelistTmp := VulnerabilitiesWhitelist{}

	whitelistBytes, err := ioutil.ReadFile(whitelistFile)
	if err != nil {
		log.Warn().Msgf("[Scanner] Could not parse Whitelist file, could not read file %v", err)
	}
	if err = yaml.Unmarshal(whitelistBytes, &whitelistTmp); err != nil {
		log.Warn().Msgf("[Scanner] Could not parse Whitelist file, could not unmarshal %v", err)
	}
	return whitelistTmp
}

// ValidateThreshold validates that the given CVE severity threshold is a valid severity
func ValidateThreshold(threshold string) {
	for severity := range SeverityMap {
		if threshold == severity {
			return
		}
	}
	log.Warn().Msgf("[Scanner] Invalid CVE severity threshold %s given", threshold)
}

// untar uses a Reader that represents a tar to untar it on the fly to a target folder
func untar(imageReader io.ReadCloser, target string) error {
	tarReader := tar.NewReader(imageReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		if !strings.HasPrefix(path, filepath.Clean(target)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", header.Name)
		}
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err = io.Copy(file, tarReader); err != nil {
			return err
		}
	}
	return nil
}

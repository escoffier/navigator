package redclair

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	log *logging.Logger
	// whitelist = VulnerabilitiesWhitelist{}
)

func init() {
	log = logging.GetLogger()
}

// IgnorePackage ...
type IgnorePackage struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

// IgnoreFile ...
type IgnoreFile struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

// CveWhite ...
type CveWhite struct {
	CVE string `json:"name"`
}

// SecretPattern ...
type SecretPattern struct {
	Description string `json:"description"`
	Type        string `json:"secret_type"`
	Value       string `json:"value"`
	Regex       *regexp.Regexp
}

// MetaScanData ...
type MetaScanData struct {
	URL               string
	Port              int
	RemoteURL         string
	RemotePort        int
	IgnoreFiles       []IgnoreFile
	IgnorePackages    []IgnorePackage
	CveWhiteList      []CveWhite
	SecretPatternList []SecretPattern
}

// InitializeRedclair ...
func InitializeRedclair(meta *MetaScanData) (re *regexp.Regexp) {
	//initializeLogger()
	log.Info().Msg("[Scanner] Redclair engine initialized")
	var fileSignatureIgnore []string

	for _, item := range meta.IgnoreFiles {
		fileSignatureIgnore = append(fileSignatureIgnore, item.Name)
	}

	re = regexp.MustCompile(strings.Join(fileSignatureIgnore, "|"))
	softwareRegExpMap = make(map[*regexp.Regexp]func([]byte) []Software, len(softwareRegExpRawMap))
	var softwareRegExpStrList []string
	for reStr, reFunc := range softwareRegExpRawMap {
		softwareRegExpMap[regexp.MustCompile(reStr)] = reFunc
		softwareRegExpStrList = append(softwareRegExpStrList, reStr)
	}
	softwareRegExp = regexp.MustCompile(strings.Join(softwareRegExpStrList, "|"))
	log.Info().Msg("[Scanner] Initialized")
	return
}

//EndClient Stop the clients
func EndClient(tmpPath string, server *http.Server) {
	os.RemoveAll(tmpPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Error().
			Err(err).
			Msg("error in shutting down HTTP server")
	}
}

func readJSONFile(path string, fieldPtr interface{}, defaultValue interface{}) {
	v := reflect.ValueOf(defaultValue)

	f, err := os.Open(path)
	if err != nil {
		log.Error().
			Err(err).
			Str("path", path).
			Msg("failed to open file")
		reflect.ValueOf(fieldPtr).Elem().Set(v)
	}
	defer f.Close()

	byteValue, _ := ioutil.ReadAll(f)
	err = json.Unmarshal(byteValue, fieldPtr)
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to read ignore files")
		reflect.ValueOf(fieldPtr).Elem().Set(v)
	}
}

//InitConfigureFiles Init Meta Scan Data
func InitConfigureFiles(opts *flag.ClairOpts) *MetaScanData {
	meta := &MetaScanData{
		URL:        opts.EndpointAddress,
		Port:       opts.EndpointClairPort,
		RemoteURL:  opts.RemoteClairAddress,
		RemotePort: opts.RemoteClairPort,
	}

	readJSONFile(opts.IgnoreFileList, &meta.IgnoreFiles, []IgnoreFile{})
	readJSONFile(opts.IgnorePackageList, &meta.IgnorePackages, []IgnorePackage{})
	readJSONFile(opts.SecretPattern, &meta.SecretPatternList, []SecretPattern{})
	readJSONFile(opts.CVEWhitelist, &meta.CveWhiteList, []CveWhite{})

	return meta
}

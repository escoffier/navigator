package redclair

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
}

// // IgnorePackage ...
// type IgnorePackage struct {
// 	Name   string `json:"name"`
// 	Reason string `json:"reason,omitempty"`
// }

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
	DescriptionEn string `json:"descriptionEn"`
	DescriptionZh string `json:"descriptionZh"`
	Type          string `json:"secret_type"`
	Value         string `json:"value"`
}

type SensitiveDescription struct {
	En string `json:"en"`
	Zh string `json:"zh"`
}

type Redclair struct {
	// External addr:port is address of tensorsec-scanner visible from clair instance
	// (in-cluster IP or service name in single cluster usage scenario).
	externalAddr string
	externalPort int

	// Address and port of clair service
	clairAddr string
	clairPort int

	// httpRootDir is a directory which contains subdirs for each scanned image.
	httpRootDir string
	server      *http.Server

	mongodb                *mongo.Database
	cve2cnnvdCollectionMux sync.Mutex

	sensitiveFilenameRegExpMap map[*regexp.Regexp]*SensitiveDescription
	sensitiveFilenameRegExp    *regexp.Regexp
	softwareRegExp             *regexp.Regexp
	softwareRegExpMap          map[*regexp.Regexp]func([]byte) []Software
	ignoreRegExp               *regexp.Regexp
	cveWhitelist               map[string]struct{}

	offlineMode bool // if true, won't download CNNVD metadata
}

func NewRedclair(opts *flag.ClairOpts, updateOpts *flag.UpdateOpts, mongodb *mongo.Database) (*Redclair, error) {
	rc := &Redclair{
		mongodb:     mongodb,
		offlineMode: updateOpts.OfflineMode,
	}
	rc.initFlags(opts)
	if err := rc.initConfigFiles(opts); err != nil {
		return nil, err
	}
	rc.initSoftwareRegexMap()
	return rc, nil
}

func (r *Redclair) initFlags(opts *flag.ClairOpts) {
	r.externalAddr = opts.EndpointAddress
	r.externalPort = opts.EndpointClairPort
	r.clairAddr = opts.RemoteClairAddress
	r.clairPort = opts.RemoteClairPort
}

func (r *Redclair) initConfigFiles(opts *flag.ClairOpts) error {
	ignoreFiles := []IgnoreFile{}
	if err := r.readJSONFile(opts.IgnoreFileList, &ignoreFiles); err != nil {
		return err
	} else {
		var fileSignatureIgnore []string
		for _, item := range ignoreFiles {
			fileSignatureIgnore = append(fileSignatureIgnore, item.Name)
		}
		r.ignoreRegExp = regexp.MustCompile(strings.Join(fileSignatureIgnore, "|"))
	}

	// TODO:
	// if err := readJSONFile(opts.IgnorePackageList, &meta.IgnorePackages); err != nil {
	// 	return err
	// }
	r.sensitiveFilenameRegExpMap = make(map[*regexp.Regexp]*SensitiveDescription)
	secretPatterns := []SecretPattern{}
	if err := r.readJSONFile(opts.SecretPattern, &secretPatterns); err != nil {
		return err
	} else {
		var sensitiveFilenameRegExpStrList []string
		for _, item := range secretPatterns {
			if item.Type == "Filename" {
				r.sensitiveFilenameRegExpMap[regexp.MustCompile(item.Value)] = &SensitiveDescription{
					En: item.DescriptionEn,
					Zh: item.DescriptionZh,
				}
				sensitiveFilenameRegExpStrList = append(sensitiveFilenameRegExpStrList, item.Value)
			}
		}
		r.sensitiveFilenameRegExp = regexp.MustCompile(strings.Join(sensitiveFilenameRegExpStrList, "|"))
	}

	cveWhites := []CveWhite{}
	if err := r.readJSONFile(opts.CVEWhitelist, &cveWhites); err != nil {
		return err
	} else {
		r.cveWhitelist = make(map[string]struct{}, len(cveWhites))
		for _, v := range cveWhites {
			log.Debug().
				Str("cve", v.CVE).
				Msg("[whitelist cve]")
			r.cveWhitelist[v.CVE] = struct{}{}
		}
		log.Info().Msgf("%+v\n", r.cveWhitelist)
	}
	return nil
}

func (r *Redclair) initSoftwareRegexMap() {
	// TODO: this should be in config file as well
	r.softwareRegExpMap = make(map[*regexp.Regexp]func([]byte) []Software, len(softwareRegExpRawMap))
	var softwareRegExpStrList []string
	for reStr, reFunc := range softwareRegExpRawMap {
		r.softwareRegExpMap[regexp.MustCompile(reStr)] = reFunc
		softwareRegExpStrList = append(softwareRegExpStrList, reStr)
	}
	r.softwareRegExp = regexp.MustCompile(strings.Join(softwareRegExpStrList, "|"))
}

func (r Redclair) readJSONFile(path string, fieldPtr interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		log.Error().
			Err(err).
			Str("path", path).
			Msg("failed to open file")
		return err
	}
	defer f.Close()

	byteValue, _ := ioutil.ReadAll(f)
	err = json.Unmarshal(byteValue, fieldPtr)
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to unmarshall file")
		return err
	}
	return nil
}

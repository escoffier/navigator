package redclair

import (
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	log *logging.Logger
)

func init() {
	log = logging.GetLogger()
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
	return rc, nil
}

func (r *Redclair) initFlags(opts *flag.ClairOpts) {
	r.externalAddr = opts.EndpointAddress
	r.externalPort = opts.EndpointClairPort
	r.clairAddr = opts.RemoteClairAddress
	r.clairPort = opts.RemoteClairPort
}

func (r *Redclair) initConfigFiles(opts *flag.ClairOpts) error {
	r.sensitiveFilenameRegExpMap = make(map[*regexp.Regexp]*SensitiveDescription)
	secretPatterns := []SecretPattern{}
	if err := r.readJSONFile(opts.SecretPattern, &secretPatterns); err != nil {
		return err
	}

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
	return nil
}

func (r Redclair) readJSONFile(path string, fieldPtr interface{}) error {
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

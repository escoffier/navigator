package cnvd

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/boltdb/bolt"
	"github.com/quay/clair/v2/database"
	"github.com/quay/clair/v2/ext/vulnmdsrc"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	// defaultDataPath string = "/data/current_cnvd.tar.gz"
	appenderName string = "CNVD"
)

type Metadata struct {
	Number      string `json:"cnvdNumber"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	RefLink     string `json:"referenceLink"`
	Description string `json:"desription"`
}

type cnvdMetadataArr *[]Metadata
type cveIDtype string

type cnvdAppender struct {
	dataPath string
	metadata map[cveIDtype]cnvdMetadataArr // one CVE may be linked to many CVNDs
	// config   cnvdConfig
	db *bolt.DB
}

// type cnvdConfig struct {
//	DataPath string
// }

func init() {
	err := register.Register("cnvd", openRegistry)
	if err != nil {
		logging.GetLogger().Err(err).Msg("init cnvd updater err")
	}
}

func openRegistry(registrableComponentConfig register.RegistrableComponentConfig, db *bolt.DB, dbPath string) (register.Registry, error) {
	var cnvd cnvdAppender
	datastore := database.MockDatastore{}
	cnvd.dataPath = filepath.Join(dbPath, "current_cnvd.tar.gz")
	// fmt.Printf("sss:%v\n", cnvd.dataPath)
	err := cnvd.BuildCache(&datastore)
	if err != nil {
		return nil, err
	}
	cnvd.db = db
	cnvd.WriteToBolt(db)
	cnvd.PurgeCache()
	return &cnvd, nil
}

func (a *cnvdAppender) Updata(wg *sync.WaitGroup) {
	defer wg.Done()
}

func (a *cnvdAppender) BuildCache(database.Datastore) error {
	logging.GetLogger().Debug().Msg("cnvd appender: BuildCache")
	a.metadata = make(map[cveIDtype]cnvdMetadataArr)

	targzFile, err := os.Open(a.dataPath)
	if err != nil {
		return fmt.Errorf("Failed to open %s: %w", a.dataPath, err)
	}
	defer targzFile.Close()

	gzipReader, err := gzip.NewReader(targzFile)
	if err != nil {
		return fmt.Errorf("Failed create gzip reader: %s: %w", a.dataPath, err)
	}
	defer gzipReader.Close()

	totalImportedVulns := 0
	totalVulnsWithoutCVE := 0
	numFiles := 0

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("Failed to advance tarReader: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			bytes, err := ioutil.ReadAll(tarReader)
			if err != nil {
				return fmt.Errorf("Failed to read bytes from %s: %w", header.Name, err)
			}
			if len(bytes) >= 20 {
				logging.GetLogger().Debug().Msgf("cnvd appender: head %s: %s...", header.Name, string(bytes[:100]))
			} else {
				logging.GetLogger().Debug().Msgf("cnvd appender: head %s: %s...", header.Name, string(bytes))
			}

			var report cnvdReport
			err = xml.Unmarshal(bytes, &report)
			if err != nil {
				return fmt.Errorf("Failed to unmarshall cnvd report %s: %w", header.Name, err)
			}

			numVulns := len(report.Vulnerabilities)

			logging.GetLogger().Debug().Msgf("cnvd appender: %s contains %d vulnerabilities", header.Name, numVulns)

			importedVulns := 0
			vulnsWithoutCVE := 0
			for _, vuln := range report.Vulnerabilities {
				if len(vuln.CVEs.CVEs) == 0 {
					vulnsWithoutCVE++
					totalVulnsWithoutCVE++
					continue
				}

				for _, cve := range vuln.CVEs.CVEs {
					cveID := cveIDtype(cve.CVENumber)
					if !strings.Contains(string(cveID), "CVE") {
						continue
					}
					if _, ok := a.metadata[cveID]; !ok {
						a.metadata[cveID] = &[]Metadata{}
					}

					entry := Metadata{
						Number:      vuln.Number,
						Title:       vuln.Title,
						Severity:    vuln.Severity,
						RefLink:     vuln.RefLink,
						Description: vuln.Description,
					}
					*a.metadata[cveID] = append(*a.metadata[cveID], entry)
					importedVulns++
					totalImportedVulns++
				}
			}

			logging.GetLogger().Debug().Msgf("cnvd appender: imported %d (out of %d) vulnerabilities from %s (%d didn't have CVE mapping)", importedVulns, numVulns, header.Name, vulnsWithoutCVE)
			numFiles++

		default:
			logging.GetLogger().Warn().Msgf("cnvd appender: unexpected header flag %v in file %s, skipping", header.Typeflag, header.Name)
		}
	}

	logging.GetLogger().Info().Msgf("cnvd appender: imported %d vulnerabilities total (%d didn't have CVE mapping) across %d files", totalImportedVulns, totalVulnsWithoutCVE, numFiles)

	return nil
}

func (a *cnvdAppender) Append(vulnName string, appenderCallback vulnmdsrc.AppendFunc) error {
	logging.GetLogger().Debug().Msgf("cnvd appender: Append for %s", vulnName)
	if cnvdMetadata, ok := a.metadata[cveIDtype(vulnName)]; ok {
		logging.GetLogger().Debug().Msgf("cnvd appender: Found meta for %s", vulnName)
		appenderCallback(appenderName, cnvdMetadata, database.UnknownSeverity)
	} else {
		logging.GetLogger().Debug().Msgf("cnvd appender: Meta not found for %s", vulnName)
	}
	return nil
}

func (a *cnvdAppender) OutputTest() {
	for k := range a.metadata {
		if len(*a.metadata[k]) > 1 {
			fmt.Println(k)
			return
		}
	}
}

func (a *cnvdAppender) WriteToBolt(db *bolt.DB) {

	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("cnvd"))
		if err != nil {
			return fmt.Errorf("CNVD:can't create cnvd bucket")
		}
		cnt := 0
		sum := 0
		for k := range a.metadata {
			// fmt.Println(k)
			v := bucket.Get([]byte(k))
			sum++
			if v != nil {
				continue
			}
			jsonStr, err := json.Marshal(a.metadata[k])
			if err != nil {
				continue
			}
			if err = bucket.Put([]byte(k), []byte(jsonStr)); err != nil {
				logging.GetLogger().Err(err).Msg("bucket put err")
				continue
			}
			cnt++
		}
		logging.GetLogger().Info().Msgf("Have %d in Map,And %d Insert To bbolt", sum, cnt)
		return err
	}); err != nil {
		logging.GetLogger().Err(err)
	}
}

func (a *cnvdAppender) PurgeCache() {
	logging.GetLogger().Debug().Msg("cnvd appender: PurgeCache")
	a.metadata = nil
}

func (a *cnvdAppender) Clean() {
	logging.GetLogger().Debug().Msg("cnvd appender: Clean")
	// I think this can be noop
}

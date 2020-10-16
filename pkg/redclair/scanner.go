package redclair

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/heroku/docker-registry-client/registry"
	dig "github.com/opencontainers/go-digest"
)

// VulnerabilitiesWhitelist ...
type VulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            // [key: CVE and value: CVE description]
	Images           map[string]map[string]string // image name with [key: CVE and value: CVE desc]
}

const (
	httpServerRootDir        = "redclair-images"
	httpServerImageDirPrefix = "image-"
)

var nvmRegExp = regexp.MustCompile(`nvm\suse\sv[0-9\.]+`)
var nvmVersionRegExp = regexp.MustCompile(`[0-9\.]+`)

// var mapLock sync.Mutex

// Pattern ...
type Pattern struct {
	Description string `json:"description"`
	SecretType  string `json:"secret_type"`
	Value       string `json:"value"`
	Regex       *regexp.Regexp
}

// ScannerConfig ...
type ScannerConfig struct {
	Experimental       bool
	LayerID            string
	LayerMetaData      string
	LayerAll           bool
	Repository         string
	ImageName          string
	WhitelistThreshold string
	ReportAll          bool
	LayerFile          string
	JSONFormat         bool
}

// LayerTreeNode ...
type LayerTreeNode struct {
	Config   string
	RepoTags []string
	Layers   []string
}

// Contain ...
func Contain(obj interface{}, target interface{}) bool {
	targetValue := reflect.ValueOf(target)
	switch reflect.TypeOf(target).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true
		}
	}

	return false
}

// SoftwareType ...
type SoftwareType string

// SourcePackage ...
const SourcePackage SoftwareType = "source"

// BinaryPackage ...
const BinaryPackage SoftwareType = "binary"

// NpmPackage ...
const NpmPackage SoftwareType = "npm"

// InfoPackage ...
const InfoPackage SoftwareType = "info"

// Software ...
type Software struct {
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	VersionFormat string       `json:"versionFormat"`
	Type          SoftwareType `json:"type"`
}

var softwareRegExpRawMap = map[string]func([]byte) []Software{
	"^var/lib/dpkg/status": parseDpkgList,
	`(^|.*\/)package.json$|(^|.*\/)package-lock.json$|(^|.*\/)yarn.lock$`: parseNode,
	`(^|.*\/)bootstrap.sh$`: parseBootstrap,
}

var nodeModuleRe = regexp.MustCompile(`.*node_module.*`)

func parseDpkgSoftware(scanner *bufio.Scanner) (binaryPackage *Software, sourcePackage *Software) {
	var SourcePackage SoftwareType = "source"
	var BinaryPackage SoftwareType = "binary"

	var dpkgSrcCaptureRegexp = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	var dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()

	var name string
	var version string
	var sourceName string
	var sourceVersion string

	for {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}

		if strings.HasPrefix(line, "Package: ") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optional)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			sourceName = md["name"]
			if md["version"] != "" {
				sourceVersion = md["version"]
			}
		} else if strings.HasPrefix(line, "Version: ") {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			version = strings.TrimPrefix(line, "Version: ")
		}

		if !scanner.Scan() {
			break
		}
	}

	if name != "" && version != "" {
		binaryPackage = &Software{name, version, "dpkg", BinaryPackage}
	}

	// Source version and names are computed from binary package names and versions
	// in dpkg.
	// Source package name:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n338
	// Source package version:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n355
	if sourceName == "" {
		sourceName = name
	}

	if sourceVersion == "" {
		sourceVersion = version
	}

	if sourceName != "" && sourceVersion != "" {
		sourcePackage = &Software{sourceName, sourceVersion, "dpkg", SourcePackage}
	}

	return
}

func parseDpkgList(data []byte) (DpkgList []Software) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		binary, source := parseDpkgSoftware(scanner)
		if binary != nil {
			DpkgList = append(DpkgList, *binary)
		}

		if source != nil {
			DpkgList = append(DpkgList, *source)
		}
	}
	return
}

func parseNode(data []byte) []Software {
	return []Software{
		{
			Name:          "node-config",
			Version:       string(data),
			VersionFormat: "",
			Type:          InfoPackage,
		},
	}
}

func parseBootstrap(data []byte) []Software {
	version := string(nvmVersionRegExp.Find(nvmRegExp.Find(data)))
	return []Software{
		{
			Name:          "npm",
			Version:       version,
			VersionFormat: "",
			Type:          NpmPackage,
		},
		{
			Name:          "node-config",
			Version:       string(data),
			VersionFormat: "",
			Type:          InfoPackage,
		},
	}
}

func (r *Redclair) ScanLayer(ctx context.Context, hub *registry.Registry, digest, parentDigest, repository string) ([]VulnerabilityInfo, []FileSignature, []Software, error) {
	pathToLayersInFS, err := r.CreateTempLayerDigestDir(digest)
	if err != nil {
		log.Error().Err(err).Str("path", pathToLayersInFS).Msg("Couldn't make image temp dir")
		return []VulnerabilityInfo{}, []FileSignature{}, []Software{}, err
	}
	defer func() {
		err := os.RemoveAll(pathToLayersInFS)
		if err != nil {
			log.Warn().Err(err).Str("path", pathToLayersInFS).Msg("Couldn't remove image temp dir")
		}
	}()
	d := dig.NewDigestFromHex(strings.Split(digest, ":")[0], strings.Split(digest, ":")[1])

	reader, err := hub.DownloadBlob(repository, d)
	if reader != nil {
		defer reader.Close()
	}
	if err != nil {
		return []VulnerabilityInfo{}, []FileSignature{}, []Software{}, err
	}

	outFile, err := os.Create(pathToLayersInFS + "/layer.tar")
	defer outFile.Close()
	_, err = io.Copy(outFile, reader)
	if err != nil {
		return []VulnerabilityInfo{}, []FileSignature{}, []Software{}, err
	}

	log.Info().Str("repository", repository).Str("layerDigest", digest).Msg("Layer saved locally")
	if err != nil {
		log.Error().
			Err(err).
			Msg("[Scanner]")
		return []VulnerabilityInfo{}, []FileSignature{}, []Software{}, err
	}

	//Analyze the layers
	pathToLayerInHTTP, err := filepath.Rel(r.httpRootDir, pathToLayersInFS)
	if err != nil {
		log.Error().
			Err(err).
			Str("httpServerRootDir", httpServerRootDir).
			Str("pathToLayersInFS", pathToLayerInHTTP).
			Msg("Failed to get relative path")
		return []VulnerabilityInfo{}, []FileSignature{}, []Software{}, err
	}

	pathToLayer := fmt.Sprintf("http://%s:%d/%s/layer.tar", r.externalAddr, r.externalPort, pathToLayerInHTTP)
	err = r.analyzeLayer(ctx, pathToLayer, digest, parentDigest)
	if err != nil {
		return []VulnerabilityInfo{}, []FileSignature{}, []Software{}, err
	}
	var imageFileSignature []FileSignature
	var imageSoftware []Software
	layerFileSignature, softwareFiles, err := generateTarHash(
		filepath.Join(pathToLayersInFS, "layer.tar"), 1<<30, 64, r.ignoreRegExp, r.softwareRegExp)
	if err != nil {
		log.Warn().Msgf("Fail to get layer signature : %s : %v",
			filepath.Join(pathToLayersInFS, "layer.tar"), err)
	}
	for _, f := range softwareFiles {
		for re, parse := range r.softwareRegExpMap {
			if re.String() == `(^|.*\/)bootstrap.sh$` && re.MatchString(f.Name) {
				tmp := parse(f.HeadContent)
				if tmp[0].Version != "" {
					imageSoftware = append(imageSoftware, tmp[0])
					tmp[1].Name = f.Name
					log.Info().Msgf("%v", tmp[0])
					imageSoftware = append(imageSoftware, tmp...)
					log.Info().Msgf("Added npm bootstrap.sh")
				} else {
					log.Info().Msgf("Ignored other bootstrap.sh")
				}
				continue
			}
			if re.String() ==
				`(^|.*\/)package.json$|(^|.*\/)package-lock.json$|(^|.*\/)yarn.lock$` &&
				re.MatchString(f.Name) {
				if nodeModuleRe.MatchString(f.Name) { // ignore files in node_module
					continue
				}
				tmp := parse(f.HeadContent)
				tmp[0].Name = f.Name
				imageSoftware = append(imageSoftware, tmp...)
				log.Info().Msgf("Added node package: %s", f.Name)
				continue
			}
			if re.MatchString(f.Name) {
				imageSoftware = append(imageSoftware, parse(f.HeadContent)...)
			}
		}
	}
	imageFileSignature = append(imageFileSignature, layerFileSignature...)
	imageFileSignature = distinctFileHash(imageFileSignature)

	vulnerabilities := r.getVulnerabilities(ctx, digest)

	return vulnerabilities, imageFileSignature, imageSoftware, nil
}

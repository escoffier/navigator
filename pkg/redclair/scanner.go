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
	"strconv"
	"strings"

	"github.com/heroku/docker-registry-client/registry"
	dig "github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"
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

// Sensitive ...
type Sensitive struct {
	Name        string `json:"name"`
	Description string `json:"description"`
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

func (r *Redclair) ScanLayer(ctx context.Context, hub *registry.Registry, digest, parentDigest, repository string) (string, []VulnerabilityInfo, []FileSignature, []Software, []Sensitive, error) {
	pathToLayersInFS, err := r.CreateTempLayerDigestDir(digest)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Str("path", pathToLayersInFS).Msg("Couldn't make image temp dir")
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, err
	}
	defer func() {
		err := os.RemoveAll(pathToLayersInFS)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Str("path", pathToLayersInFS).Msg("Couldn't remove image temp dir")
		}
	}()
	d := dig.NewDigestFromHex(strings.Split(digest, ":")[0], strings.Split(digest, ":")[1])

	reader, err := hub.DownloadBlob(repository, d)
	if reader != nil {
		defer reader.Close()
	}
	if err != nil {
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, err
	}

	outFile, err := os.Create(pathToLayersInFS + "/layer.tar")
	defer outFile.Close()
	_, err = io.Copy(outFile, reader)
	if err != nil {
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, err
	}

	info, err := os.Stat(pathToLayersInFS + "/layer.tar")
	if err != nil {
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, err
	}

	zerolog.Ctx(ctx).Info().
		Str("repository", repository).
		Str("layerDigest", digest).
		Int64("size", info.Size()).
		Str("path", pathToLayersInFS+"/layer.tar").
		Msg("Layer saved locally")
	if err != nil {
		zerolog.Ctx(ctx).Error().
			Err(err).
			Msg("[Scanner]")
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, err
	}

	//Analyze the layers
	pathToLayerInHTTP, err := filepath.Rel(r.httpRootDir, pathToLayersInFS)
	if err != nil {
		zerolog.Ctx(ctx).Error().
			Err(err).
			Str("httpServerRootDir", httpServerRootDir).
			Str("pathToLayersInFS", pathToLayerInHTTP).
			Msg("Failed to get relative path")
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, err
	}

	pathToLayer := fmt.Sprintf("http://%s:%d/%s/layer.tar", r.externalAddr, r.externalPort, pathToLayerInHTTP)
	err = r.analyzeLayer(ctx, pathToLayer, digest, parentDigest)
	if err != nil {
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, err
	}
	var imageFileSignature []FileSignature
	var imageSoftware []Software
	layerFileSignature, softwareFiles, sensitiveFiles, err := walkTarFiles(
		filepath.Join(pathToLayersInFS, "layer.tar"), 1<<30, 64, r.ignoreRegExp, r.softwareRegExp, r.sensitiveFilenameRegExp)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Msgf("Fail to get layer signature : %s : %v",
			filepath.Join(pathToLayersInFS, "layer.tar"), err)
	}
	for _, f := range softwareFiles {
		for re, parse := range r.softwareRegExpMap {
			if re.String() == `(^|.*\/)bootstrap.sh$` && re.MatchString(f.Name) {
				tmp := parse(f.HeadContent)
				if tmp[0].Version != "" {
					imageSoftware = append(imageSoftware, tmp[0])
					tmp[1].Name = f.Name
					zerolog.Ctx(ctx).Info().Msgf("%v", tmp[0])
					imageSoftware = append(imageSoftware, tmp...)
					zerolog.Ctx(ctx).Info().Msgf("Added npm bootstrap.sh")
				} else {
					zerolog.Ctx(ctx).Info().Msgf("Ignored other bootstrap.sh")
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
				zerolog.Ctx(ctx).Info().Msgf("Added node package: %s", f.Name)
				continue
			}
			if re.MatchString(f.Name) {
				imageSoftware = append(imageSoftware, parse(f.HeadContent)...)
			}
		}
	}
	var imageSensitiveFiles = r.getSensitiveFiles(sensitiveFiles)

	imageFileSignature = append(imageFileSignature, layerFileSignature...)
	imageFileSignature = distinctFileHash(imageFileSignature)

	namespaceName, vulnerabilities := r.getVulnerabilities(ctx, digest)

	err = r.enrichWithCNNVD(ctx, vulnerabilities)
	if err != nil {
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, fmt.Errorf("Failed to enrich vuln info with CNNVD: %w", err)
	}

	err = r.recalculateSeverity(ctx, vulnerabilities)
	if err != nil {
		return "", []VulnerabilityInfo{}, []FileSignature{}, []Software{}, []Sensitive{}, fmt.Errorf("Failed to recalculate severity: %w", err)
	}

	return namespaceName, vulnerabilities, imageFileSignature, imageSoftware, imageSensitiveFiles, nil
}

func (r *Redclair) getSensitiveFiles(sensitiveFiles []FileSignature) []Sensitive {
	imageSensitiveFiles := make([]Sensitive, 0)
	for _, f := range sensitiveFiles {
		for re, description := range r.sensitiveFilenameRegExpMap {
			if re.MatchString(f.Name) {
				imageSensitiveFiles = append(imageSensitiveFiles, Sensitive{
					Name:        f.Name,
					Description: description,
				})
			}
		}
	}
	return imageSensitiveFiles
}

func (r *Redclair) recalculateSeverity(ctx context.Context, vulns []VulnerabilityInfo) error {
	for i, vuln := range vulns {

		if vuln.CVSSv2Score == "" {
			continue
		}

		// It's a string that contains one decimal place.
		// Convert to an int without decimals by removing the "."
		// (effectively multiplies by 10)
		s := strings.ReplaceAll(vuln.CVSSv2Score, ".", "")
		score, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("Failed to parse CVSSv2 score: %w", err)
		}

		// Based on ranges defined for CVSS v3.0, because they're more fine-grained.
		// https://nvd.nist.gov/vuln-metrics/cvss
		if score == 0 {
			vulns[i].Severity = SeverityNone
		} else if score >= 1 && score <= 9 {
			vulns[i].Severity = SeverityNegligible
		} else if score >= 10 && score <= 39 {
			vulns[i].Severity = SeverityLow
		} else if score >= 40 && score <= 69 {
			vulns[i].Severity = SeverityMedium
		} else if score >= 70 && score <= 89 {
			vulns[i].Severity = SeverityHigh
		} else if score >= 90 {
			vulns[i].Severity = SeverityCritical
		} else {
			vulns[i].Severity = SeverityUnknown
		}
	}
	return nil
}

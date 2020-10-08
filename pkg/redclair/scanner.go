package redclair

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
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

// Scan orchestrates the scanning process of an image
func (r *Redclair) Scan(
	config ScannerConfig,
) (*VulnerabilityReport, []FileSignature, []Software, error) {

	pathToLayersInFS, err := r.CreateTempImageDirIn(r.httpRootDir)
	if err != nil {
		log.Error().Err(err).Str("path", pathToLayersInFS).Msg("Couldn't make image temp dir")
		return &VulnerabilityReport{}, []FileSignature{}, []Software{}, err
	}
	defer func() {
		err := os.RemoveAll(pathToLayersInFS)
		if err != nil {
			log.Warn().Err(err).Str("path", pathToLayersInFS).Msg("Couldn't remove image temp dir")
		}
	}()

	imageID, LayerIDs, err := SaveDockerImage(config.ImageName, pathToLayersInFS)
	log.Info().Str("imageID", imageID).Str("layers", fmt.Sprintf("%v", LayerIDs)).Msgf("Docker image saved")
	if err != nil {
		log.Error().
			Err(err).
			Msg("[Scanner]")
		return &VulnerabilityReport{}, []FileSignature{}, []Software{}, err
	}

	//Analyze the layers
	pathToLayersInHTTP, err := filepath.Rel(r.httpRootDir, pathToLayersInFS)
	if err != nil {
		log.Error().
			Err(err).
			Str("httpServerRootDir", httpServerRootDir).
			Str("pathToLayersInFS", pathToLayersInFS).
			Msg("Failed to get relative path")
		return &VulnerabilityReport{}, []FileSignature{}, []Software{}, err
	}

	// TODO error handling here, wtf
	r.analyzeLayers(pathToLayersInHTTP, config.ImageName, LayerIDs)

	log.Info().Msgf("Generating file signature in %s ...", config.ImageName)
	var imageFileSignature []FileSignature
	var imageSoftware []Software
	for _, v := range LayerIDs {
		layerFileSignature, softwareFiles, err := GenerateTarHash(
			filepath.Join(pathToLayersInFS, v, "layer.tar"), 1<<30, 64, r.ignoreRegExp, r.softwareRegExp)
		if err != nil {
			log.Warn().Msgf("Fail to get layer signature : %s : %v",
				filepath.Join(pathToLayersInFS, v, "layer.tar"), err)
			continue
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
	}
	log.Info().Msgf("Signed %s", config.ImageName)
	imageFileSignature = DistinctFileHash(imageFileSignature)

	vulnerabilities := r.GetVulnerabilities(config.ImageName, LayerIDs)

	//Check vulnerabilities against Whitelist and report
	// unapproved := CheckForUnapprovedVulnerabilities(
	// 	config.ImageName, vulnerabilities, config.Whitelist, config.WhitelistThreshold)

	return &VulnerabilityReport{
		config.ImageName,
		imageID,
		[]string{},
		vulnerabilities,
	}, imageFileSignature, imageSoftware, nil
}

// CheckForUnapprovedVulnerabilities checks if the found vulnerabilities are approved or not
// in the Whitelist
// func CheckForUnapprovedVulnerabilities(
// 	imageName string,
// 	vulnerabilities []VulnerabilityInfo,
// 	whitelist VulnerabilitiesWhitelist,
// 	whitelistThreshold string,
// ) []string {
// 	unapproved := []string{}
// 	imageVulnerabilities := GetImageVulnerabilities(imageName, whitelist.Images)

// 	for i := 0; i < len(vulnerabilities); i++ {
// 		vulnerability := vulnerabilities[i].Vulnerability
// 		severity := vulnerabilities[i].Severity
// 		vulnerable := true

// 		//Check if the vulnerability has a severity less than our threshold severity
// 		if SeverityMap[severity] > SeverityMap[whitelistThreshold] {
// 			vulnerable = false
// 		}

// 		//Check if the vulnerability exists in the GeneralWhitelist
// 		if vulnerable {
// 			if _, exists := whitelist.GeneralWhitelist[vulnerability]; exists {
// 				vulnerable = false
// 			}
// 		}

// 		//If not in GeneralWhitelist check if the vulnerability exists in the imageVulnerabilities
// 		if vulnerable && len(imageVulnerabilities) > 0 {
// 			if _, exists := imageVulnerabilities[vulnerability]; exists {
// 				vulnerable = false
// 			}
// 		}
// 		if vulnerable {
// 			unapproved = append(unapproved, vulnerability)
// 		}
// 	}
// 	return unapproved
// }

// GetImageVulnerabilities returns image specific Whitelist of vulnerabilities from
// whitelistImageVulnerabilities
func GetImageVulnerabilities(
	imageName string,
	whitelistImageVulnerabilities map[string]map[string]string,
) map[string]string {
	var imageVulnerabilities map[string]string
	// TODO:
	// there is a bug here if it is a private registry with a custom port registry:777/ubuntu:tag
	imageWithoutVersion := strings.Split(imageName, ":")
	if val, exists := whitelistImageVulnerabilities[imageWithoutVersion[0]]; exists {
		imageVulnerabilities = val
	}
	return imageVulnerabilities
}

package redclair

import (
	"bufio"
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// VulnerabilitiesWhitelist ...
type VulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            // [key: CVE and value: CVE description]
	Images           map[string]map[string]string // image name with [key: CVE and value: CVE desc]
}

const tmpPrefix = "redclair-client-"

// const apikey = "acdb7268710f2ed4cf161308cc3525467ddab512fc1731adbac1eaff14f6b4ef"
// const apiurl = "https://www.virustotal.com/vtapi/v2/"

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
	LayerDivide        bool
	LayerID            string
	LayerMetaData      string
	LayerAll           bool
	ImageName          string
	Whitelist          VulnerabilitiesWhitelist
	ClairURL           string
	ScannerIP          string
	ScannerPort        int
	ReportFile         string
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

var softwareRegExp *regexp.Regexp
var softwareRegExpMap map[*regexp.Regexp]func([]byte) []Software

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

// GetRandomString ...
func GetRandomString(n int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < n; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

// Scan orchestrates the scanning process of an image
func Scan(
	config ScannerConfig,
	tmpPath string,
	noPrint bool,
	ignoreRegExp *regexp.Regexp,
) (*VulnerabilityReport, []FileSignature, []Software, error) {
	if tmpPath == "" {
		tmpPath = CreateTmpPath(tmpPrefix)
		defer os.RemoveAll(tmpPath)

		server := HTTPFileServer(tmpPath, config.ScannerPort)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				log.Error().
					Err(err).
					Msg("error in shutting down HTTP server")
			}
		}()
	}

	if config.LayerID != "" {
		// Check if in Experimental mode
		if config.Experimental {
			log.Warn().Msgf(`
[Scanner] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[Scanner] !! Layer scan may cause DANGEROUS race in some condition,                            !!
[Scanner] !! you should use whole image scan option when you import this package,              !!
[Scanner] !! or we recommend you to use the binary executing way for single layer scan safely. !!
[Scanner] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[Scanner] Target layer is %s`, config.LayerID)
		} else {
			log.Warn().Msg("[Scanner] Layer Scan only works in Experimental mode")
		}

		return &VulnerabilityReport{}, []FileSignature{}, []Software{}, nil
	}

	imageID, LayerIDs, err := SaveDockerImage(config.ImageName, tmpPath)
	log.Info().Msgf("%v, %v", imageID, LayerIDs)
	if err != nil {
		log.Error().
			Err(err).
			Msg("[Scanner]")
		return &VulnerabilityReport{}, []FileSignature{}, []Software{}, err
	}

	//Analyze the layers
	AnalyzeLayers(config.ImageName, LayerIDs, config.ClairURL, config.ScannerIP, config.ScannerPort)

	log.Info().Msgf("[Scanner] Generating file signature in %s ...", config.ImageName)
	var imageFileSignature []FileSignature
	var imageSoftware []Software
	for _, v := range LayerIDs {
		log.Info().Msgf("%v, %v", ignoreRegExp, softwareRegExp)
		layerFileSignature, softwareFiles, err := GenerateTarHash(
			filepath.Join(tmpPath, v, "layer.tar"), 1<<30, 64, ignoreRegExp, softwareRegExp)
		if err != nil {
			log.Warn().Msgf("[Scanner] Fail to get layer signature : %s : %v",
				filepath.Join(tmpPath, v, "layer.tar"), err)
			continue
		}
		for _, f := range softwareFiles {
			for re, parse := range softwareRegExpMap {
				if re.String() == `(^|.*\/)bootstrap.sh$` && re.MatchString(f.Name) {
					tmp := parse(f.HeadContent)
					if tmp[0].Version != "" {
						imageSoftware = append(imageSoftware, tmp[0])
						tmp[1].Name = f.Name
						log.Info().Msgf("[Scanner] %v", tmp[0])
						imageSoftware = append(imageSoftware, tmp...)
						log.Info().Msgf("[Scanner] Added npm bootstrap.sh")
					} else {
						log.Info().Msgf("[Scanner] Ignored other bootstrap.sh")
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
					log.Info().Msgf("[Scanner] Added node package: %s", f.Name)
					continue
				}
				if re.MatchString(f.Name) {
					imageSoftware = append(imageSoftware, parse(f.HeadContent)...)
				}
			}
		}
		imageFileSignature = append(imageFileSignature, layerFileSignature...)
	}
	log.Info().Msgf("[Scanner] Signed %s", config.ImageName)
	imageFileSignature = DistinctFileHash(imageFileSignature)

	if config.LayerDivide {
		vulnerabilitiesGroup := GetAllLayerVulnerabilities(config.ClairURL, LayerIDs)
		ReportToConsoleOfDividedLayer(config.ImageName, vulnerabilitiesGroup, config.JSONFormat)
		ReportToFileOfDividedLayer(
			config.ImageName, vulnerabilitiesGroup, config.LayerFile, config.ReportFile)
		return &VulnerabilityReport{}, []FileSignature{}, []Software{}, nil
	}

	vulnerabilities := GetVulnerabilities(config.ImageName, config.ClairURL, LayerIDs)

	//Check vulnerabilities against Whitelist and report
	unapproved := CheckForUnapprovedVulnerabilities(
		config.ImageName, vulnerabilities, config.Whitelist, config.WhitelistThreshold)

	// Report vulnerabilities
	if !noPrint {
		ReportToConsole(
			config.ImageName,
			vulnerabilities,
			unapproved,
			config.ReportAll,
			config.JSONFormat,
			imageID,
		)
	}
	ReportToFile(config.ImageName, vulnerabilities, unapproved, config.ReportFile, imageID)

	return &VulnerabilityReport{
		config.ImageName,
		imageID,
		unapproved,
		vulnerabilities,
	}, imageFileSignature, imageSoftware, nil
}

// CheckForUnapprovedVulnerabilities checks if the found vulnerabilities are approved or not
// in the Whitelist
func CheckForUnapprovedVulnerabilities(
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	whitelist VulnerabilitiesWhitelist,
	whitelistThreshold string,
) []string {
	unapproved := []string{}
	imageVulnerabilities := GetImageVulnerabilities(imageName, whitelist.Images)

	for i := 0; i < len(vulnerabilities); i++ {
		vulnerability := vulnerabilities[i].Vulnerability
		severity := vulnerabilities[i].Severity
		vulnerable := true

		//Check if the vulnerability has a severity less than our threshold severity
		if SeverityMap[severity] > SeverityMap[whitelistThreshold] {
			vulnerable = false
		}

		//Check if the vulnerability exists in the GeneralWhitelist
		if vulnerable {
			if _, exists := whitelist.GeneralWhitelist[vulnerability]; exists {
				vulnerable = false
			}
		}

		//If not in GeneralWhitelist check if the vulnerability exists in the imageVulnerabilities
		if vulnerable && len(imageVulnerabilities) > 0 {
			if _, exists := imageVulnerabilities[vulnerability]; exists {
				vulnerable = false
			}
		}
		if vulnerable {
			unapproved = append(unapproved, vulnerability)
		}
	}
	return unapproved
}

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

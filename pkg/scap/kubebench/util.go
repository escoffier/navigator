package kubebench

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

var (
	// Print colors
	colors = map[check.State]*color.Color{
		check.PASS: color.New(color.FgGreen),
		check.FAIL: color.New(color.FgRed),
		check.WARN: color.New(color.FgYellow),
		check.INFO: color.New(color.FgBlue),
	}
)

var psFunc func(string) string
var statFunc func(string) (os.FileInfo, error)
var getBinariesFunc func(*viper.Viper, check.NodeType) (map[string]string, error)

//TypeMap Type map
var TypeMap = map[string][]string{
	"ca":         {"cafile", "defaultcafile"},
	"kubeconfig": {"kubeconfig", "defaultkubeconfig"},
	"service":    {"svc", "defaultsvc"},
	"config":     {"confs", "defaultconf"},
}

func init() {
	psFunc = ps
	statFunc = os.Stat
	getBinariesFunc = getBinaries
}

func exitWithError(err error) {
	log.Error().Msgf("\n%v\n", err)
	os.Exit(1)
}

func continueWithError(err error, msg string) string {
	if err != nil {
		log.Error().Msgf("%v\n", err)
	}

	if msg != "" {
		log.Error().Msgf("%s\n", msg)
	}

	return ""
}

func cleanIDs(list string) map[string]bool {
	list = strings.Trim(list, ",")
	ids := strings.Split(list, ",")

	set := make(map[string]bool)

	for _, id := range ids {
		id = strings.Trim(id, " ")
		set[id] = true
	}

	return set
}

// ps execs out to the ps command; it's separated into a function so we can write tests
func ps(proc string) string {
	log.Error().Msgf("ps - proc: %q", proc)
	cmd := exec.Command("/bin/ps", "-C", proc, "-o", "cmd", "--no-headers")
	out, err := cmd.Output()
	if err != nil {
		continueWithError(fmt.Errorf("%s: %s", cmd.Args, err), "")
	}

	log.Error().Msgf("ps - returning: %q", string(out))
	return string(out)
}

// getBinaries finds which of the set of candidate executables are running.
// It returns an error if one mandatory executable is not running.
func getBinaries(v *viper.Viper, c check.NodeType) (map[string]string, error) {
	binmap := make(map[string]string)

	for _, component := range v.GetStringSlice("components") {
		s := v.Sub(component)
		if s == nil {
			continue
		}

		optional := s.GetBool("optional")
		bins := s.GetStringSlice("bins")
		if len(bins) > 0 {
			bin, err := findExecutable(bins)
			if err != nil && !optional {
				return nil, fmt.Errorf("unable to detect running programs for component %q", component)
			}

			// Default the executable name that we'll substitute to the name of the component
			if bin == "" {
				bin = component
				log.Info().Msgf("Component %s not running", component)
			} else {
				log.Info().Msgf("Component %s uses running binary %s", component, bin)
			}
			binmap[component] = bin
		}
	}

	return binmap, nil
}

// getConfigFilePath locates the config files we should be using for CIS version
func getConfigFilePath(benchmarkVersion string, filename string) (path string, err error) {
	log.Info().Msgf("Looking for config specific CIS version %q", benchmarkVersion)

	path = filepath.Join(cfgDir, benchmarkVersion)
	file := filepath.Join(path, filename)
	log.Info().Msgf("Looking for file: %s", file)

	if _, err := os.Stat(file); err != nil {
		log.Info().Msgf("error accessing config file: %q error: %v\n", file, err)
		return "", fmt.Errorf("no test files found <= benchmark version: %s", benchmarkVersion)
	}

	return path, nil
}

// getYamlFilesFromDir returns a list of yaml files in the specified directory, ignoring config.yaml
// func getYamlFilesFromDir(path string) (names []string, err error) {
// 	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}

// 		_, name := filepath.Split(path)
// 		if name != "" && name != "config.yaml" && filepath.Ext(name) == ".yaml" {
// 			names = append(names, path)
// 		}

// 		return nil
// 	})
// 	return names, err
// }

// decrementVersion decrements the version number
// We want to decrement individually even through versions where we don't supply test files
// just in case someone wants to specify their own test files for that version
func decrementVersion(version string) string {
	split := strings.Split(version, ".")
	if len(split) < 2 {
		return ""
	}
	minor, err := strconv.Atoi(split[1])
	if err != nil {
		return ""
	}
	if minor <= 1 {
		return ""
	}
	split[1] = strconv.Itoa(minor - 1)
	return strings.Join(split, ".")
}

// getFiles finds which of the set of candidate files exist
func getFiles(v *viper.Viper, fileType string) map[string]string {
	filemap := make(map[string]string)
	mainOpt := TypeMap[fileType][0]
	defaultOpt := TypeMap[fileType][1]

	for _, component := range v.GetStringSlice("components") {
		s := v.Sub(component)
		if s == nil {
			continue
		}

		// See if any of the candidate files exist
		file := findConfigFile(s.GetStringSlice(mainOpt))
		if file == "" {
			if s.IsSet(defaultOpt) {
				file = s.GetString(defaultOpt)
				log.Info().Msgf("Using default %s file name '%s' for component %s", fileType, file, component)
			} else {
				// Default the file name that we'll substitute to the name of the component
				log.Info().Msgf("Missing %s file for %s", fileType, component)
				file = component
			}
		} else {
			log.Info().Msgf("Component %s uses %s file '%s'", component, fileType, file)
		}

		filemap[component] = file
	}

	return filemap
}

// verifyBin checks that the binary specified is running
func verifyBin(bin string) bool {
	// Strip any quotes
	bin = strings.Trim(bin, "'\"")

	// bin could consist of more than one word
	// We'll search for running processes with the first word, and then check the whole
	// proc as supplied is included in the results
	proc := strings.Fields(bin)[0]
	out := psFunc(proc)

	// There could be multiple lines in the ps output
	// The binary needs to be the first word in the ps output,
	// except that it could be preceded by a path
	// e.g. /usr/bin/kubelet is a match for kubelet
	// but apiserver is not a match for kube-apiserver
	reFirstWord := regexp.MustCompile(`^(\S*\/)*` + bin)
	lines := strings.Split(out, "\n")
	log.Info().Msgf("verifyBin - lines(%d)", len(lines))
	for _, l := range lines {
		log.Info().Msgf("reFirstWord.Match(%s)\n\n\n\n", l)
		if reFirstWord.Match([]byte(l)) {
			return true
		}
	}

	return false
}

// fundConfigFile looks through a list of possible config files and finds the first one that exists
func findConfigFile(candidates []string) string {
	for _, c := range candidates {
		_, err := statFunc(c)
		if err == nil {
			return c
		}
		if !os.IsNotExist(err) {
			exitWithError(fmt.Errorf("error looking for file %s: %v", c, err))
		}
	}

	return ""
}

// findExecutable looks through a list of possible executable names and
// finds the first one that's running
func findExecutable(candidates []string) (string, error) {
	for _, c := range candidates {
		if verifyBin(c) {
			return c, nil
		}
		log.Info().Msgf("executable '%s' not running", c)
	}

	return "", fmt.Errorf("no candidates running")
}

func multiWordReplace(s string, subname string, sub string) string {
	f := strings.Fields(sub)
	if len(f) > 1 {
		sub = "'" + sub + "'"
	}

	return strings.Replace(s, subname, sub, -1)
}

func getKubeVersion() (string, error) {
	if k8sVer, err := getKubeVersionFromRESTAPI(); err == nil {
		log.Info().Msgf("Kubernetes REST API Reported version: %s", k8sVer)
		return k8sVer, nil
	}

	// These executables might not be on the user's path.
	_, err := exec.LookPath("kubectl")

	if err != nil {
		_, err = exec.LookPath("kubelet")
		if err != nil {
			// Search for the kubelet binary all over the filesystem and run the first match
			// to get the kubernetes version
			cmd := exec.Command(
				"/bin/sh",
				"-c",
				"`find / -type f -executable -name kubelet 2>/dev/null | grep -m1 .` --version",
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				return getVersionFromKubeletOutput(string(out)), nil
			}

			return "", fmt.Errorf("unable to find the programs kubectl or kubelet in the PATH")
		}
		return getKubeVersionFromKubelet(), nil
	}

	return getKubeVersionFromKubectl(), nil
}

func getKubeVersionFromKubectl() string {
	cmd := exec.Command("kubectl", "version", "--short")
	out, err := cmd.CombinedOutput()
	if err != nil {
		continueWithError(fmt.Errorf("%s", out), "")
	}

	return getVersionFromKubectlOutput(string(out))
}

func getKubeVersionFromKubelet() string {
	cmd := exec.Command("kubelet", "--version")
	out, err := cmd.CombinedOutput()

	if err != nil {
		continueWithError(fmt.Errorf("%s", out), "")
	}

	return getVersionFromKubeletOutput(string(out))
}

func getVersionFromKubectlOutput(s string) string {
	serverVersionRe := regexp.MustCompile(`Server Version: v(\d+.\d+)`)
	subs := serverVersionRe.FindStringSubmatch(s)
	if len(subs) < 2 {
		log.Info().Msgf("Unable to get Kubernetes version from kubectl, using default version: %s",
			defaultKubeVersion)
		return defaultKubeVersion
	}
	return subs[1]
}

func getVersionFromKubeletOutput(s string) string {
	serverVersionRe := regexp.MustCompile(`Kubernetes v(\d+.\d+)`)
	subs := serverVersionRe.FindStringSubmatch(s)
	if len(subs) < 2 {
		log.Info().Msgf("Unable to get Kubernetes version from kubelet, using default version: %s",
			defaultKubeVersion)
		return defaultKubeVersion
	}
	return subs[1]
}

func makeSubstitutions(s string, ext string, m map[string]string) string {
	for k, v := range m {
		subst := "$" + k + ext
		if v == "" {
			log.Info().Msgf("No substitution for '%s'\n", subst)
			continue
		}
		log.Info().Msgf("Substituting %s with '%s'\n", subst, v)
		s = multiWordReplace(s, subst, v)
	}

	return s
}

func isEmpty(str string) bool {
	return len(strings.TrimSpace(str)) == 0
}

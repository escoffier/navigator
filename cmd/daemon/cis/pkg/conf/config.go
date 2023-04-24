package conf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	psFunc   func(string) string
	statFunc func(string) (os.FileInfo, error)
)

func init() {
	psFunc = ps
	statFunc = os.Stat
}

// FindExecutable looks through a list of possible executable names and finds the first one that's running
func FindExecutable(candidates []string) (string, error) {
	for _, c := range candidates {
		if verifyBin(c) {
			return c, nil
		}
		logging.GetLogger().Info().Str("executable", c).Msg("executable not running")
	}

	return "", fmt.Errorf("no candidates running")
}

// ps execs out to the ps command; it's separated into a function so we can write tests
func ps(proc string) string {
	// TODO: truncate proc to 15 chars
	// See https://github.com/aquasecurity/kube-bench/issues/328#issuecomment-506813344
	logging.GetLogger().Info().Str("proc", proc).Msg("ps - proc")
	cmd := exec.Command("/bin/ps", "-C", proc, "-o", "cmd", "--no-headers")
	out, err := cmd.Output()
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("cmd args: ", fmt.Sprintf("%v", cmd.Args)).Msg("ps - error")
	}
	logging.GetLogger().Info().Str("out", string(out)).Msg("ps - out")
	return string(out)
}

// VerifyBin checks that the binary specified is running
func verifyBin(bin string) bool {

	// Strip any quotes
	bin = strings.Trim(bin, "'\"")

	// bin could consist of more than one word
	// We'll search for running processes with the first word, and then check the whole
	// proc as supplied is included in the results
	proc := strings.Fields(bin)[0]
	out := psFunc(proc)

	// There could be multiple lines in the ps output
	// The binary needs to be the first word in the ps output, except that it could be preceded by a path
	// e.g. /usr/bin/kubelet is a match for kubelet
	// but apiserver is not a match for kube-apiserver
	reFirstWord := regexp.MustCompile(`^(\S*\/)*` + bin)
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		logging.GetLogger().Info().Str("line", l).Msg("reFirstWord.Match")
		if reFirstWord.Match([]byte(l)) {
			return true
		}
	}

	return false
}

// FindConfigFile looks through a list of possible config files and finds the first one that exists
func FindConfigFile(candidates []string) string {
	for _, c := range candidates {
		_, err := statFunc(c)
		if err == nil {
			return c
		}
		if !os.IsNotExist(err) {
			utils.ExitWithError(fmt.Errorf("error looking for file %s: %v", c, err))
		}
	}

	return ""
}

func MakeSubstitutions(s string, ext string, m map[string]string) (string, []string) {
	substitutions := make([]string, 0)
	for k, v := range m {
		subst := "$" + k + ext
		if v == "" {
			logging.GetLogger().Info().Str("substitution", subst).Msg("no substitution")
			continue
		}
		logging.GetLogger().Info().Str("substitution", subst).Str("value", v).Msg("substituting")
		beforeS := s
		s = multiWordReplace(s, subst, v)
		if beforeS != s {
			substitutions = append(substitutions, v)
		}
	}

	return s, substitutions
}

func multiWordReplace(s string, subname string, sub string) string {
	f := strings.Fields(sub)
	if len(f) > 1 {
		sub = "'" + sub + "'"
	}

	return strings.Replace(s, subname, sub, -1)
}

// GetConfigFilePath locates the config files we should be using for CIS version
func GetConfigFilePath(benchmarkVersion string, cfgDir, filename string) (path string, err error) {
	logging.GetLogger().Info().Str("benchmarkVersion", benchmarkVersion).Str("cfgDir", cfgDir).Str("filename", filename).Msg("GetConfigFilePath")

	path = filepath.Join(cfgDir, benchmarkVersion)
	file := filepath.Join(path, filename)
	logging.GetLogger().Info().Str("file", file).Msg("Looking for file")

	if _, err := os.Stat(file); err != nil {
		logging.GetLogger().Err(err).Str("file", file).Msg("error accessing config file")
		return "", fmt.Errorf("no test files found <= benchmark version: %s", benchmarkVersion)
	}

	return path, nil
}

func MergeConfig(path string) error {
	viper.SetConfigFile(path + "/config.yaml")
	err := viper.MergeInConfig()
	if err != nil {
		if os.IsNotExist(err) {
			logging.GetLogger().Info().Str("path", path).Msg("No version-specific config.yaml file")
		} else {
			return fmt.Errorf("couldn't read config file %s: %v", path+"/config.yaml", err)
		}
	}

	logging.GetLogger().Info().Str("path", path).Msg("Merged in config file")

	return nil
}

func LoadVersionMapping(v *viper.Viper) (map[string]string, error) {
	kubeToBenchmarkMap := v.GetStringMapString("version_mapping")
	if kubeToBenchmarkMap == nil || (len(kubeToBenchmarkMap) == 0) {
		return nil, fmt.Errorf("config file is missing 'version_mapping' section")
	}

	return kubeToBenchmarkMap, nil
}

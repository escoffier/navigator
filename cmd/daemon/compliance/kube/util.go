package kube

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/cis/conf"
	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	getBinariesFunc func(*viper.Viper, check.NodeType) (map[string]string, error)
	TypeMap         = map[string][]string{
		"ca":         {"cafile", "defaultcafile"},
		"kubeconfig": {"kubeconfig", "defaultkubeconfig"},
		"service":    {"svc", "defaultsvc"},
		"config":     {"confs", "defaultconf"},
	}
	nc check.NewCommand
)

func init() {
	getBinariesFunc = getBinaries
	nc = func() *exec.Cmd { return exec.Command("sh") }
}

type Platform struct {
	Name    string
	Version string
}

func (p Platform) String() string {
	return fmt.Sprintf("%s-%s", p.Name, p.Version)
}

// getBinaries finds which of the set of candidate executables are running.
// It returns an error if one mandatory executable is not running.
func getBinaries(v *viper.Viper, nodetype check.NodeType) (map[string]string, error) {
	binmap := make(map[string]string)

	for _, component := range v.GetStringSlice("components") {
		s := v.Sub(component)
		if s == nil {
			continue
		}

		optional := s.GetBool("optional")
		bins := s.GetStringSlice("bins")
		if len(bins) > 0 {
			bin, err := conf.FindExecutable(nc, bins)
			if err != nil && !optional {
				logging.Get().Warn().Msg(buildComponentMissingErrorMessage(nodetype, component, bins))
				return nil, fmt.Errorf("unable to detect running programs for component %q", component)
			}

			// Default the executable name that we'll substitute to the name of the component
			if bin == "" {
				bin = component
				logging.Get().Info().Msg(fmt.Sprintf("Component %s not running", component))
			} else {
				logging.Get().Info().Msg(fmt.Sprintf("Component %s uses running binary %s", component, bin))
			}
			binmap[component] = bin
		}
	}

	return binmap, nil
}

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
func getFiles(v *viper.Viper, fileType, pathPrefix string) (map[string]string, error) {
	m, err := conf.GetFiles(v, TypeMap, fileType, pathPrefix)
	if err != nil {
		logging.Get().Warn().Err(err).Msg("getFiles error")
		return nil, err
	}

	return m, nil
}

const missingKubectlKubeletMessage = `
Unable to find the programs kubectl or kubelet in the PATH.
These programs are used to determine which version of Kubernetes is running.
Make sure the /usr/local/mount-from-host/bin directory is mapped to the container,
either in the job.yaml file, or Docker command.

For job.yaml:
...
- name: usr-bin
  mountPath: /usr/local/mount-from-host/bin
...

For docker command:
   docker -v $(which kubectl):/usr/local/mount-from-host/bin/kubectl ....

Alternatively, you can specify the version with --version
   kube-bench --version <VERSION> ...
`

func getKubeVersion() (*KubeVersion, error) {
	if k8sVer, err := getKubeVersionFromRESTAPI(getKubernetesURL()); err == nil {
		logging.Get().Info().Msg(fmt.Sprintf("Kubernetes REST API Reported version: %s", k8sVer))
		return k8sVer, nil
	}

	// These executables might not be on the user's path.
	_, err := exec.LookPath("kubectl")
	if err != nil {
		logging.Get().Debug().Msgf("Error locating kubectl: %s", err)
		_, err = exec.LookPath("kubelet")
		if err != nil {
			logging.Get().Debug().Msgf("Error locating kubelet: %s", err)
			// Search for the kubelet binary all over the filesystem and run the first match to get the kubernetes version
			cmd := exec.Command("/bin/sh", "-c", "`find / -type f -executable -name kubelet 2>/dev/null | grep -m1 .` --version")
			out, err := cmd.CombinedOutput()
			if err == nil {
				logging.Get().Debug().Msgf("Found kubelet and query kubernetes version is: %s", string(out))
				return getVersionFromKubeletOutput(string(out)), nil
			}

			logging.Get().Warn().Msg(missingKubectlKubeletMessage)
			logging.Get().Warn().Msg("unable to find the programs kubectl or kubelet in the PATH")
			logging.Get().Warn().Msgf("Cant detect version, assuming default %s", defaultKubeVersion)
			return &KubeVersion{baseVersion: defaultKubeVersion}, nil
		}
		return getKubeVersionFromKubelet(), nil
	}

	return getKubeVersionFromKubectl(), nil
}

func getKubeVersionFromKubectl() *KubeVersion {
	cmd := exec.Command("kubectl", "version", "-o", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		logging.Get().Info().Msgf("Failed to query kubectl: %s", err)
		logging.Get().Info().Msg(err.Error())
	}

	return getVersionFromKubectlOutput(string(out))
}

func getKubeVersionFromKubelet() *KubeVersion {
	cmd := exec.Command("kubelet", "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		logging.Get().Info().Msgf("Failed to query kubelet: %s", err)
		logging.Get().Info().Msg(err.Error())
	}

	return getVersionFromKubeletOutput(string(out))
}

func getVersionFromKubectlOutput(s string) *KubeVersion {
	logging.Get().Info().Msgf("Kubectl output: %s", s)
	type versionResult struct {
		ServerVersion VersionResponse
	}
	vrObj := &versionResult{}
	if err := json.Unmarshal([]byte(s), vrObj); err != nil {
		logging.Get().Info().Msg(err.Error())
		if strings.Contains(s, "The connection to the server") {
			msg := fmt.Sprintf(`Warning: Kubernetes version was not auto-detected because kubectl could not connect to the Kubernetes server. This may be because the kubeconfig information is missing or has credentials that do not match the server. Assuming default version %s`, defaultKubeVersion)
			fmt.Fprintln(os.Stderr, msg)
		}
		logging.Get().Warn().Msg(fmt.Sprintf("Unable to get Kubernetes version from kubectl, using default version: %s", defaultKubeVersion))
		return &KubeVersion{baseVersion: defaultKubeVersion}
	}
	sv := vrObj.ServerVersion
	return &KubeVersion{
		Major:      sv.Major,
		Minor:      sv.Minor,
		GitVersion: sv.GitVersion,
	}
}

func getVersionFromKubeletOutput(s string) *KubeVersion {
	logging.Get().Info().Msgf("Kubelet output: %s", s)
	serverVersionRe := regexp.MustCompile(`Kubernetes v(\d+.\d+)`)
	subs := serverVersionRe.FindStringSubmatch(s)
	if len(subs) < 2 {
		logging.Get().Warn().Msg(fmt.Sprintf("Unable to get Kubernetes version from kubelet, using default version: %s", defaultKubeVersion))
		return &KubeVersion{baseVersion: defaultKubeVersion}
	}
	return &KubeVersion{baseVersion: subs[1]}
}

func buildComponentMissingErrorMessage(nodetype check.NodeType, component string, bins []string) string {
	errMessageTemplate := `
Unable to detect running programs for component %q
The following %q programs have been searched, but none of them have been found:
%s

These program names are provided in the config.yaml, section '%s.%s.bins'
`

	var componentRoleName, componentType string
	switch nodetype {

	case check.NODE:
		componentRoleName = "worker node"
		componentType = "node"
	case check.ETCD:
		componentRoleName = "etcd node"
		componentType = "etcd"
	default:
		componentRoleName = "master node"
		componentType = "master"
	}

	binList := ""
	for _, bin := range bins {
		binList = fmt.Sprintf("%s\t- %s\n", binList, bin)
	}

	return fmt.Sprintf(errMessageTemplate, component, componentRoleName, binList, componentType, component)
}
func getPlatformInfo() Platform {
	openShiftInfo := getOpenShiftInfo()
	if openShiftInfo.Name != "" && openShiftInfo.Version != "" {
		return openShiftInfo
	}

	dceInfo := getDceInfo()
	if dceInfo.Name != "" && dceInfo.Version != "" {
		return dceInfo
	}

	kv, err := getKubeVersion()
	if err != nil {
		logging.Get().Info().Msg(err.Error())
		return Platform{}
	}
	return getPlatformInfoFromVersion(kv)
}

func getPlatformInfoFromVersion(kv *KubeVersion) Platform {
	versionRe := regexp.MustCompile(`v(\d+\.\d+)\.\d+[-+](\w+)(?:[.\-])\w+`)
	subs := versionRe.FindStringSubmatch(kv.GitVersion)
	if len(subs) < 3 {
		return Platform{
			Name:    "kube",
			Version: kv.BaseVersion(),
		}
	}
	return Platform{
		Name:    subs[2],
		Version: subs[1],
	}
}

func getPlatformBenchmarkVersion(platform Platform) string {
	logging.Get().Debug().Msgf("getPlatformBenchmarkVersion platform: %s", platform)
	switch platform.Name {
	case "eks":
		return "eks-1.1.0"
	case "gke":
		switch platform.Version {
		case "1.15", "1.16", "1.17", "1.18", "1.19":
			return "gke-1.0"
		default:
			return "gke-1.2.0"
		}
	case "aliyun":
		return "ack-1.0"
	case "ocp":
		switch platform.Version {
		case "3.10":
			return "rh-0.7"
		case "4.1":
			return "rh-1.0"
		}
	case "dce":
		return "dce-4.0"
	}
	return ""
}

func getOpenShiftInfo() Platform {
	logging.Get().Info().Msg("Checking for oc")
	_, err := exec.LookPath("oc")

	if err == nil {
		cmd := exec.Command("oc", "version")
		out, err := cmd.CombinedOutput()

		if err == nil {
			versionRe := regexp.MustCompile(`oc v(\d+\.\d+)`)
			subs := versionRe.FindStringSubmatch(string(out))
			if len(subs) < 1 {
				versionRe = regexp.MustCompile(`Client Version:\s*(\d+\.\d+)`)
				subs = versionRe.FindStringSubmatch(string(out))
			}
			if len(subs) > 1 {
				logging.Get().Info().Msgf("OCP output '%s' \nplatform is %s \nocp %v", string(out),
					getPlatformInfoFromVersion(&KubeVersion{GitVersion: string(out)}), subs[1])
				ocpBenchmarkVersion, err := getOcpValidVersion(subs[1])
				if err == nil {
					return Platform{Name: "ocp", Version: ocpBenchmarkVersion}
				} else {
					logging.Get().Warn().Msgf("Can't get getOcpValidVersion: %v", err)
				}
			} else {
				logging.Get().Warn().Msgf("Can't parse version output: %v", subs)
			}
		} else {
			logging.Get().Warn().Msgf("Can't use oc command: %v", err)
		}
	} else {
		logging.Get().Warn().Msgf("Can't find oc command: %v", err)
	}
	return Platform{}
}

func getOcpValidVersion(ocpVer string) (string, error) {
	ocpOriginal := ocpVer

	for !util.IsEmpty(ocpVer) {
		logging.Get().Debug().Msg(fmt.Sprintf("getOcpBenchmarkVersion check for ocp: %q \n", ocpVer))
		if ocpVer == "3.10" || ocpVer == "4.1" {
			logging.Get().Warn().Msg(fmt.Sprintf("getOcpBenchmarkVersion found valid version for ocp: %q \n", ocpVer))
			return ocpVer, nil
		}
		ocpVer = decrementVersion(ocpVer)
	}

	logging.Get().Warn().Msg(fmt.Sprintf("getOcpBenchmarkVersion unable to find a match for: %q", ocpOriginal))
	return "", fmt.Errorf("unable to find a matching Benchmark Version match for ocp version: %s", ocpOriginal)
}

func getDceInfo() Platform {
	_, err := getKubeVersionFromRESTAPI(getDceVersionURL())
	if err != nil {
		return Platform{}
	}

	return Platform{Name: "dce", Version: "4.0"}
}

func getDceVersionURL() string {
	k8sHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	k8sPort := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if !util.IsEmpty(k8sHost) && !util.IsEmpty(k8sPort) {
		return fmt.Sprintf("https://%s:%s/version/dce", k8sHost, k8sPort)
	}

	return "https://kubernetes.default.svc/version/dce"
}

func getVariateValue(ext string, dst, m map[string]string) {
	for k, v := range m {
		subst := "$" + k + ext
		if v == "" {
			continue
		}
		dst[subst] = v
	}
}

func getSummaryTotals(controlsCollection []*check.Controls) check.Summary {
	var totalSummary check.Summary
	for _, controls := range controlsCollection {
		summary := controls.Summary
		totalSummary.Fail = totalSummary.Fail + summary.Fail
		totalSummary.Warn = totalSummary.Warn + summary.Warn
		totalSummary.Pass = totalSummary.Pass + summary.Pass
		totalSummary.Info = totalSummary.Info + summary.Info
	}
	return totalSummary
}

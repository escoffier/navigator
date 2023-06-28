package host

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/logging"
)

var nc check.NewCommand

func init() {
	nc = func() *exec.Cmd { return exec.Command("sh") }
}

type Platform struct {
	Name    string
	Version string
}

func (p Platform) String() string {
	return fmt.Sprintf("%s-%s", p.Name, p.Version)
}

func getPlatformInfo() Platform {
	platform, err := getLinuxSystem()
	if err != nil {
		logging.Get().Warn().Msgf("Version check failed: %s\nAlternatively, you can specify the version with --version", err)
		return Platform{}
	}

	return platform
}

func getLinuxSystem() (platform Platform, err error) {
	out, err := check.RunCommandWithOutput(nc, "cat /etc/os-release")
	if err != nil {
		return Platform{}, err
	} else {
		output := strings.ToLower(string(out))
		output = strings.Replace(output, `"`, "", -1)
		output = strings.Replace(output, `_id`, "", -1) // version_id kills the regex

		flagRe := regexp.MustCompile(`id=([^ \n]*)`)
		vals := flagRe.FindStringSubmatch(output)
		if len(vals) > 1 {
			platform.Name = vals[1]
		}

		platform.Version = getPlatformVersion(output, platform.Name)
	}

	return platform, nil
}

func getBootLoader() (boot string, err error) {
	out, err := check.RunCommandWithOutput(nc, "grub-install --version")
	if err != nil {
		out, err = check.RunCommandWithOutput(nc, "ls /boot | grep grub")
		if err != nil {
			out, err = check.RunCommandWithOutput(nc, "ls /boot/boot | grep grub")
			if err != nil {
				return "", err
			}
		}
	}

	output := strings.ToLower(string(out))

	if strings.Contains(output, "grub2") {
		boot = "grub2"
	} else if strings.Contains(output, "grub") {
		boot = "grub"
	}

	return boot, nil
}

func getSystemLogManager() (syslog string, err error) {
	out, err := check.RunCommandWithOutput(nc, "sudo lsof +D /var/log | grep /var/log/syslog | cut -f1 -d' '")
	if err != nil {
		out, err = check.RunCommandWithOutput(nc, "service rsyslog status")
		if err != nil {
			return "", err
		}
		output := strings.ToLower(string(out))
		if strings.Contains(output, "active (running)") {
			syslog = "rsyslog"
		} else {
			syslog = "syslog-ng"

		}

	} else {
		output := strings.ToLower(string(out))
		if strings.Contains(output, "syslog-ng") {
			syslog = "syslog-ng"
		} else {
			syslog = "rsyslog"
		}
	}

	return syslog, nil
}

func getLSM() (lsm string, err error) {
	out, err := check.RunCommandWithOutput(nc, "sudo apparmor_status")
	if err != nil {
		out, err = check.RunCommandWithOutput(nc, "sestatus")
		if err != nil {
			return "", err
		} else {
			output := strings.ToLower(out)
			space := regexp.MustCompile(`\s+`)
			output = space.ReplaceAllString(output, " ")
			if strings.Contains(output, "selinux status: enabled") {
				lsm = "selinux"
			}
		}
	} else {
		output := strings.ToLower(out)
		if strings.Contains(output, "apparmor module is loaded") {
			lsm = "apparmor"
		}
	}
	return lsm, nil
}

func getNftables() (ntf string, err error) {
	_, err = check.RunCommandWithOutput(nc, "nft -v")
	if err != nil {
		return "false", err
	}

	return "true", nil
}

func getPlatformVersion(output, platform string) string {
	flagRe := regexp.MustCompile(`version[_id]*=([^ \n]*)`)
	vals := flagRe.FindStringSubmatch(output)
	if len(vals) > 1 {
		switch platform {
		case "rhel":
			return vals[1][:1] // Get the major version only, examaple: 7.6 will return 7
		case "ubuntu":
			return vals[1][:2] // Get the major version only, examaple: 18.04 will return 18
		case "centos":
			return vals[1][:1] // Get the major version only, examaple: 7 will return 7
		default:
			return ""
		}
	}

	return ""
}

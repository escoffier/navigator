package memshell

import (
	"os"
	"os/exec"
	"regexp"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
)

// Rule represents a single command structure in the YAML
type Rule struct {
	Key       string   `yaml:"key"`
	Hid       string   `yaml:"hid"`
	Cmds      []string `yaml:"cmds"`
	Condition string   `yaml:"condition"`
	Info      struct {
		Name struct {
			En string `yaml:"en"`
			Zh string `yaml:"zh"`
		} `yaml:"name"`
		Desc struct {
			En string `yaml:"en"`
			Zh string `yaml:"zh"`
		} `yaml:"desc"`
		Suggestion struct {
			En string `yaml:"en"`
			Zh string `yaml:"zh"`
		} `yaml:"suggestion"`
	} `yaml:"info"`
}

// ReadYAML reads the YAML file and returns a slice of Command structs
func ReadYAML(filename string) ([]Rule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	err = yaml.Unmarshal(data, &rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// ExecuteCommands executes the commands and returns the output
func ExecuteCommands(cmds []string) ([]string, error) {
	var results []string
	for _, cmdStr := range cmds {
		cmd := exec.Command("sh", "-c", cmdStr)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return results, err
		}
		results = append(results, string(output))
	}
	return results, nil
}

func ParseCmdline(cmdline string, envVars map[string]string) (string, []string) {
	if cmdline == "" {
		return "", nil
	}

	equalIndex := 0
	execCmd := []string{}
	resultVar := ""
	equalIndex = strings.Index(cmdline, "=")
	fitCmd := ""
	if equalIndex > strings.Index(cmdline, "\"") {
		// like - mbean | grep "j2eeType=Filter"
		equalIndex = 0
	}
	if equalIndex > 0 {
		resultVar = strings.Trim(cmdline[:equalIndex], " ")
		fitCmd = strings.Trim(cmdline[equalIndex+1:], " ")
	} else {
		fitCmd = cmdline
	}
	logging.GetLogger().Debug().Msgf("fitCmd: %s", fitCmd)

	re := regexp.MustCompile(`\$(\w+)`)
	matches := re.FindStringSubmatch(fitCmd)
	fillVar := ""
	fillVarIndex := strings.Index(fitCmd, "$")
	if fillVarIndex == -1 {
		execCmd = append(execCmd, fitCmd)
		goto ret
	}

	if len(matches) > 1 {
		fillVar = "$" + matches[1]
	}
	logging.GetLogger().Debug().Msgf("fillVar: %s", fillVar)
	if _, ok := envVars[fillVar]; !ok {
		logging.GetLogger().Warn().Msgf("envVars[%s] is empty", fillVar)
		execCmd = append(execCmd, fitCmd)
		goto ret
	}
	for _, line := range strings.Split(envVars[fillVar], "\n") {
		execCmd = append(execCmd, strings.ReplaceAll(fitCmd, fillVar, line))
	}
ret:
	return resultVar, execCmd
}

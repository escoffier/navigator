package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/util/jsonpath"
)

type binOp string

const (
	and                   binOp = "and"
	or                          = "or"
	defaultArraySeparator       = ","
)

type AuditUsed string

const (
	AuditCommand AuditUsed = "auditCommand"
	AuditConfig  AuditUsed = "auditConfig"
	AuditEnv     AuditUsed = "auditEnv"
)

type testItem struct {
	Flag             string
	Env              string
	Path             string
	Output           string
	Value            string
	Set              bool
	Compare          compare
	isMultipleOutput bool
	auditUsed        AuditUsed
}

type (
	envTestItem  testItem
	pathTestItem testItem
	flagTestItem testItem
)

type compare struct {
	Op    string
	Value string
}

// testOutput represents output from tests
type testOutput struct {
	TestResult     bool
	FlagFound      bool
	ActualResult   string
	ExpectedResult string
}

func failTestItem(s string) *testOutput {
	return &testOutput{TestResult: false, ActualResult: s}
}

func (t testItem) value() string {
	if t.auditUsed == AuditConfig {
		return t.Path
	}

	if t.auditUsed == AuditEnv {
		return t.Env
	}

	return t.Flag
}

func (t testItem) findValue(s string) (match bool, value string, err error) {
	if t.auditUsed == AuditEnv {
		et := envTestItem(t)
		return et.findValue(s)
	}

	if t.auditUsed == AuditConfig {
		pt := pathTestItem(t)
		return pt.findValue(s)
	}

	ft := flagTestItem(t)
	return ft.findValue(s)
}

func (t flagTestItem) findValue(s string) (match bool, value string, err error) {
	if t.Flag == "" {
		return true, s, nil
	}

	match = strings.Contains(s, t.Flag)
	if match {
		pttns := []string{
			`(?:^|[\s]+|\$)"?` + `(` + t.Flag + `)` + `"?\s*[=:][\r\t\f\v ]*"(.*)"`,
			`(?:^|[\s]+|\$)"?` + `(` + t.Flag + `)` + `"?\s*[=:][\r\t\f\v\n ]*([^\s]*)`,
			`(?:^|[\s]+|\$)"?` + `(` + t.Flag + `)` + `"?\s+([^-\s]+)`,
			`(?:^|[\s]+|\$)` + `(` + t.Flag + `)` + `(?:[\s]|$)`,
		}
		for _, pttn := range pttns {
			flagRe := regexp.MustCompile(pttn)
			vals := flagRe.FindStringSubmatch(s)

			if l := len(vals); l > 0 {
				if l == 3 && vals[2] != "" {
					value = vals[2]
					break
				} else if l == 2 {
					// --bool-flag
					if strings.HasPrefix(t.Flag, "--") {
						value = "true"
					} else {
						value = vals[1]
					}
					break
				}
			}
		}
		//
		// if value == "" {
		// 	err = fmt.Errorf("invalid flag in testItem definition: %s", s)
		// }
	}

	logging.GetLogger().Info().Msgf("In flagTestItem.findValue %s", value)

	return match, value, err
}

func (t pathTestItem) findValue(s string) (match bool, value string, err error) {
	var jsonInterface interface{}

	err = unmarshal(s, &jsonInterface)
	if err != nil {
		return false, "", fmt.Errorf("failed to load YAML or JSON from input \"%s\": %v", s, err)
	}

	value, err = executeJSONPath(t.Path, &jsonInterface)
	if err != nil {
		return false, "", fmt.Errorf("unable to parse path expression \"%s\": %v", t.Path, err)
	}

	logging.GetLogger().Info().Msgf("In pathTestItem.findValue %s", value)
	match = value != ""
	return match, value, err
}

func (t envTestItem) findValue(s string) (match bool, value string, err error) {
	if s != "" && t.Env != "" {
		r, _ := regexp.Compile(fmt.Sprintf("%s=.*(?:$|\\n)", t.Env))
		out := r.FindString(s)
		out = strings.Replace(out, "\n", "", 1)
		out = strings.Replace(out, fmt.Sprintf("%s=", t.Env), "", 1)

		if len(out) > 0 {
			match = true
			value = out
		} else {
			match = false
			value = ""
		}
	}
	logging.GetLogger().Info().Msgf("In envTestItem.findValue %s", value)
	return match, value, nil
}

func (t *testItem) execute(s string) *testOutput {
	result := &testOutput{}
	s = strings.TrimRight(s, " \n")

	// If the test has output that should be evaluated for each row
	var output []string
	if t.isMultipleOutput {
		output = strings.Split(s, "\n")
	} else {
		output = []string{s}
	}

	for _, op := range output {
		result = t.evaluate(op)
		// If the test failed for the current row, no need to keep testing for this output
		if !result.TestResult {
			break
		}
	}

	result.ActualResult = s
	return result
}

// tests combine test items with binary operations to evaluate results.
type tests struct {
	TestItems []*testItem `yaml:"test_items"`
	BinOp     binOp       `yaml:"bin_op"`
}

func toNumeric(a, b string) (c, d int, err error) {
	c, err = strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return -1, -1, fmt.Errorf("toNumeric - error converting %s: %s", a, err)
	}
	d, err = strconv.Atoi(strings.TrimSpace(b))
	if err != nil {
		return -1, -1, fmt.Errorf("toNumeric - error converting %s: %s", b, err)
	}

	return c, d, nil
}

func (t *testItem) evaluate(s string) *testOutput {
	result := &testOutput{}

	match, value, err := t.findValue(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		return failTestItem(err.Error())
	}

	if t.Set {
		if match && t.Compare.Op != "" {
			result.ExpectedResult, result.TestResult = compareOp(t.Compare.Op, value, t.Compare.Value, t.value())
		} else {
			result.ExpectedResult = fmt.Sprintf("'%s' is present", t.value())
			result.TestResult = match
		}
	} else {
		result.ExpectedResult = fmt.Sprintf("'%s' is not present", t.value())
		result.TestResult = !match
	}

	result.FlagFound = match
	isExist := "exists"
	if !result.FlagFound {
		isExist = "does not exist"
	}

	switch t.auditUsed {
	case AuditCommand:
		logging.GetLogger().Info().Msgf("Flag '%s' %s", t.Flag, isExist)
	case AuditConfig:
		logging.GetLogger().Info().Msgf("Path '%s' %s", t.Path, isExist)
	case AuditEnv:
		logging.GetLogger().Info().Msgf("Env '%s' %s", t.Env, isExist)
	default:
		logging.GetLogger().Error().Msgf("Error with identify audit used %s", t.auditUsed)
	}

	return result
}

func compareOp(tCompareOp, flagVal, tCompareValue, flagName string) (string, bool) {
	expectedResultPattern := ""
	testResult := false

	logging.GetLogger().Info().Msgf("Actual value flag '%s' = '%s'", flagName, flagVal)

	switch tCompareOp {
	case "eq":
		expectedResultPattern = "'%s' is equal to '%s'"
		value := strings.ToLower(flagVal)
		// In case the result should be empty, changing the status to indicate "No output"
		if tCompareValue == "" && flagVal == "" {
			expectedResultPattern = "%s%sNo output"
		}
		// Do case insensitive comparison for booleans ...
		if value == "false" || value == "true" {
			testResult = value == tCompareValue
		} else {
			testResult = flagVal == tCompareValue
		}

	case "noteq":
		expectedResultPattern = "'%s' is not equal to '%s'"
		value := strings.ToLower(flagVal)
		// Do case insensitive comparison for booleans ...
		if value == "false" || value == "true" {
			testResult = !(value == tCompareValue)
		} else {
			testResult = !(flagVal == tCompareValue)
		}

	case "gt", "gte", "lt", "lte":
		a, b, err := toNumeric(flagVal, tCompareValue)
		if err != nil {
			expectedResultPattern = "Invalid Number(s) used for comparison: '%s' '%s'"
			logging.GetLogger().Info().Msgf("Not numeric value - flag: %q - compareValue: %q %v\n", flagVal, tCompareValue, err)
			return fmt.Sprintf(expectedResultPattern, flagVal, tCompareValue), false
		}
		switch tCompareOp {
		case "gt":
			expectedResultPattern = "'%s' is greater than %s"
			testResult = a > b

		case "gte":
			expectedResultPattern = "'%s' is greater or equal to %s"
			testResult = a >= b

		case "lt":
			expectedResultPattern = "'%s' is lower than %s"
			testResult = a < b

		case "lte":
			expectedResultPattern = "'%s' is lower or equal to %s"
			testResult = a <= b
		}

	case "has":
		expectedResultPattern = "'%s' has '%s'"
		testResult = strings.Contains(flagVal, tCompareValue)

	case "nothave":
		expectedResultPattern = "'%s' does not have '%s'"
		testResult = !strings.Contains(flagVal, tCompareValue)

	case "regex":
		expectedResultPattern = "'%s' matched by regex expression '%s'"
		opRe := regexp.MustCompile(tCompareValue)
		testResult = opRe.MatchString(flagVal)

	case "valid_elements":
		expectedResultPattern = "'%s' contains valid elements from '%s'"
		s := splitAndRemoveLastSeparator(flagVal, defaultArraySeparator)
		target := splitAndRemoveLastSeparator(tCompareValue, defaultArraySeparator)
		testResult = allElementsValid(s, target)

	case "bitmask":
		expectedResultPattern = "'%s' has permissions " + flagVal + ", expected %s or more restrictive"
		requested, err := strconv.ParseInt(flagVal, 8, 64)
		if err != nil {
			logging.GetLogger().Info().Msgf("Not numeric value - flag: %q - compareValue: %q %v\n", flagVal, tCompareValue, err)
			return fmt.Sprintf("Not numeric value - flag: %s", flagVal), false
		}
		max, err := strconv.ParseInt(tCompareValue, 8, 64)
		if err != nil {
			logging.GetLogger().Info().Msgf("Not numeric value - flag: %q - compareValue: %q %v\n", flagVal, tCompareValue, err)
			return fmt.Sprintf("Not numeric value - flag: %s", tCompareValue), false
		}
		testResult = (max & requested) == requested
	}

	if expectedResultPattern == "" {
		return expectedResultPattern, testResult
	}

	return fmt.Sprintf(expectedResultPattern, flagName, tCompareValue), testResult
}

func allElementsValid(s, t []string) bool {
	sourceEmpty := len(s) == 0
	targetEmpty := len(t) == 0

	if sourceEmpty && targetEmpty {
		return true
	}

	// XOR comparison -
	//     if either value is empty and the other is not empty,
	//     not all elements are valid
	if (sourceEmpty || targetEmpty) && !(sourceEmpty && targetEmpty) {
		return false
	}

	for _, sv := range s {
		found := false
		for _, tv := range t {
			if sv == tv {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func splitAndRemoveLastSeparator(s, sep string) []string {
	cleanS := strings.TrimRight(strings.TrimSpace(s), sep)
	if len(cleanS) == 0 {
		return []string{}
	}

	ts := strings.Split(cleanS, sep)
	for i := range ts {
		ts[i] = strings.TrimSpace(ts[i])
	}

	return ts
}

func unmarshal(s string, jsonInterface *interface{}) error {
	// We don't know whether it's YAML or JSON but
	// we can just try one then the other
	data := []byte(s)
	err := json.Unmarshal(data, jsonInterface)
	if err != nil {
		err := yaml.Unmarshal(data, jsonInterface)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeJSONPath(path string, jsonInterface interface{}) (string, error) {
	j := jsonpath.New("jsonpath")
	j.AllowMissingKeys(true)
	err := j.Parse(path)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	err = j.Execute(buf, jsonInterface)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (t *testItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type buildTest testItem

	// Make Set parameter to be treu by default.
	newTestItem := buildTest{Set: true}
	err := unmarshal(&newTestItem)
	if err != nil {
		return err
	}
	*t = testItem(newTestItem)
	return nil
}

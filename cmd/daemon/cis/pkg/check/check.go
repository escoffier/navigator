package check

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/execcmd"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// State is the state of a control check.
type State string

// NodeType indicates the type of node (master, node).
type NodeType string

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL = "FAIL"
	// WARN could not carry out check.
	WARN = "WARN"
	// INFO informational message
	INFO = "INFO"
	// SKIP for when a check should be skipped.
	SKIP = "skip"

	// MASTER a master node
	MASTER NodeType = "master"
	// NODE a node
	NODE NodeType = "node"
	// FEDERATED a federated deployment.
	FEDERATED NodeType = "federated"

	// ETCD an etcd node
	ETCD NodeType = "etcd"
	// CONTROLPLANE a control plane node
	CONTROLPLANE NodeType = "controlplane"
	// POLICIES a node to run policies from
	POLICIES NodeType = "policies"
	// MANAGEDSERVICES a node to run managedservices from
	MANAGEDSERVICES NodeType = "managedservices"

	// MANUAL Check Type
	MANUAL = "manual"
)

// SubCheck additional check to be performed.
// type SubCheck struct {
// 	Audit       string              `yaml:"audit"`
// 	AuditEnv    string              `yaml:"audit_env"`
// 	AuditConfig string              `yaml:"audit_config"`
// 	Tests       *tests              `yaml:"tests"`
// 	Remediation string              `yaml:"remediation"`
// 	Constraints map[string][]string `yaml:"constraints"`
// }

// Check contains information about a recommendation.
type Check struct {
	ID   string `yaml:"id" json:"test_number"`
	Text string `json:"test_desc" yaml:"text"`
	// SubChecks         []*SubCheck `yaml:"sub_checks" json:"-"`
	Constraints       map[string][]string `json:"-" yaml:"constraints"`
	Audit             string              `json:"audit"`
	AuditEnv          string              `json:"audit_env" yaml:"audit_env"`
	AuditConfig       string              `json:"audit_config" yaml:"audit_config"`
	Type              string              `json:"type"`
	Tests             *tests              `json:"-"`
	Set               bool                `json:"-"`
	Remediation       string              `json:"-"`
	TestInfo          []string            `json:"test_info"`
	State             `json:"status"`
	ActualValue       string `json:"actual_value"`
	Scored            bool   `json:"scored"`
	IsMultiple        bool   `yaml:"use_multiple_values"`
	ExpectedResult    string `json:"expected_result"`
	Reason            string `json:"reason,omitempty"`
	AuditOutput       string `json:"-"`
	AuditEnvOutput    string `json:"-"`
	AuditConfigOutput string `json:"-"`
	DisableEnvTesting bool   `json:"-"`
	Envs              []string
}

// Runner wraps the basic Run method.
type Runner interface {
	// Run runs a given check and returns the execution state.
	Run(c *Check) State
	RunWithEnvs(c *Check, envs []string) State
}

// NewRunner constructs a default Runner.
func NewRunner() Runner {
	return &defaultRunner{}
}

type defaultRunner struct{}

func (r *defaultRunner) Run(c *Check) State {
	return c.run()
}

func (r *defaultRunner) RunWithEnvs(c *Check, envs []string) State {
	return c.runWithEnvs(envs)
}

func (c *Check) runWithEnvs(envs []string) State {
	c.Envs = envs
	return c.run()
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) run() State {
	logging.GetLogger().Info().Msgf("-----   Running check %v   -----", c.ID)
	// Since this is an Scored check
	// without tests return a 'WARN' to alert
	// the user that this check needs attention
	if c.Scored && strings.TrimSpace(c.Type) == "" && c.Tests == nil {
		c.Reason = "There are no tests"
		c.State = WARN
		logging.GetLogger().Warn().Str("reason", c.Reason).Msgf("-----   Finished check %v   -----", c.ID)
		return c.State
	}

	// If check type is skip, force result to INFO
	if c.Type == SKIP {
		c.Reason = "Test marked as skip"
		c.State = INFO
		logging.GetLogger().Info().Str("reason", c.Reason).Msgf("-----   Finished check %v   -----", c.ID)
		return c.State
	}

	// If check type is manual force result to WARN
	if c.Type == MANUAL {
		c.Reason = "Test marked as a manual test"
		c.State = WARN
		logging.GetLogger().Warn().Str("reason", c.Reason).Msgf("-----   Finished check %v   -----", c.ID)
		return c.State
	}

	// If there aren't any tests defined this is a FAIL or WARN
	if c.Tests == nil || len(c.Tests.TestItems) == 0 {
		c.Reason = "No tests defined"
		if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
		logging.GetLogger().Warn().Str("reason", c.Reason).Msgf("-----   Finished check %v   -----", c.ID)
		return c.State
	}

	// Command line parameters override the setting in the config file, so if we get a good result from the Audit command that's all we need to run
	var finalOutput *testOutput
	var lastCommand string

	lastCommand, err := c.runAuditCommands()
	if err == nil {
		finalOutput, err = c.execute()
	}

	if finalOutput != nil {
		if finalOutput.TestResult {
			c.State = PASS
		} else {
			if c.Scored {
				c.State = FAIL
			} else {
				c.State = WARN
			}
		}

		c.ActualValue = finalOutput.ActualResult
		c.ExpectedResult = finalOutput.ExpectedResult
	}

	if err != nil {
		c.Reason = err.Error()
		if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
		logging.GetLogger().Info().Msgf("-----   Finished check %v   -----", c.ID)
	}

	if finalOutput != nil {
		logging.GetLogger().Info().Msgf("Command: %q TestResult: %t State: %q \n", lastCommand, finalOutput.TestResult, c.State)
	} else {
		logging.GetLogger().Info().Msgf("Command: %q TestResult: %t State: %q \n", lastCommand, false, c.State)
	}

	if c.Reason != "" {
		logging.GetLogger().Info().Msgf("Reason: %q \n", c.Reason)
	}
	return c.State
}

func (c *Check) runAuditCommands() (lastCommand string, err error) {
	// Always run auditEnvOutput if needed
	if c.AuditEnv != "" {
		c.AuditEnvOutput, err = execcmd.RunCommandWithEnv(c.AuditEnv, c.Envs)
		if err != nil {
			return c.AuditEnv, err
		}
	}

	// Run the audit command and auditConfig commands, if present
	c.AuditOutput, err = execcmd.RunCommandWithEnv(c.Audit, c.Envs)
	if err != nil {
		return c.Audit, err
	}

	c.AuditConfigOutput, err = execcmd.RunCommandWithEnv(c.AuditConfig, c.Envs)
	return c.AuditConfig, err
}

// Execute perfoms benchmark tests
func (c *Check) execute() (*testOutput, error) {
	finalOutput := &testOutput{}

	ts := c.Tests
	res := make([]testOutput, len(ts.TestItems))
	expectedResultArr := make([]string, len(res))

	logging.GetLogger().Info().Msgf("Running %d test_items", len(ts.TestItems))
	for i, t := range ts.TestItems {
		t.isMultipleOutput = c.IsMultiple

		// Try with the auditOutput first, and if that's not found, try the auditConfigOutput
		t.auditUsed = AuditCommand
		result := *(t.execute(c.AuditOutput))

		// Check for AuditConfigOutput only if AuditConfig is set
		if !result.FlagFound && c.AuditConfig != "" {
			// t.isConfigSetting = true
			t.auditUsed = AuditConfig
			result = *(t.execute(c.AuditConfigOutput))
			if !result.FlagFound && t.Env != "" {
				t.auditUsed = AuditEnv
				result = *(t.execute(c.AuditEnvOutput))
			}
		}

		if !result.FlagFound && t.Env != "" {
			t.auditUsed = AuditEnv
			result = *(t.execute(c.AuditEnvOutput))
		}
		logging.GetLogger().Info().Msgf("Test %d: %s", i, result.TestResult)
		res[i] = result
		expectedResultArr[i] = res[i].ExpectedResult
	}

	var result bool
	// If no binary operation is specified, default to AND
	switch ts.BinOp {
	default:
		logging.GetLogger().Info().Msgf("unknown binary operator for tests %s\n", ts.BinOp)
		finalOutput.ActualResult = fmt.Sprintf("unknown binary operator for tests %s\n", ts.BinOp)
		return finalOutput, fmt.Errorf("unknown binary operator for tests %s", ts.BinOp)
	case and, "":
		result = true
		for i := range res {
			result = result && res[i].TestResult
		}
		// Generate an AND expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " AND ")
	case or:
		result = false
		for i := range res {
			result = result || res[i].TestResult
		}
		// Generate an OR expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " OR ")
	}

	finalOutput.TestResult = result
	finalOutput.ActualResult = res[0].ActualResult

	logging.GetLogger().Info().Msgf("Returning from execute on tests: finalOutput %#v", finalOutput)
	return finalOutput, nil
}

// func getFirstValidSubCheck(subChecks []*SubCheck, definedConstraints map[string][]string) (subCheck *SubCheck) {
// 	for _, sc := range subChecks {
// 		isSubCheckOk := true
// 		for testConstraintKey, testConstraintVals := range sc.Constraints {
// 			isSubCheckOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, definedConstraints)
//
// 			// If the sub check is not compatible with the constraints, move to the next one
// 			if !isSubCheckOk {
// 				break
// 			}
// 		}
//
// 		if isSubCheckOk {
// 			return sc
// 		}
// 	}
//
// 	return nil
// }

func isSubCheckCompatible(testConstraintKey string, testConstraintVals []string, definedConstraints map[string][]string) bool {
	definedConstraintsVals := definedConstraints[testConstraintKey]

	// If the constraint's key is not defined - the check is not compatible
	if !(len(definedConstraintsVals) > 0) {
		return false
	}

	// For each constraint of the check under the specific key, check if its defined
	for _, val := range testConstraintVals {
		if contains(definedConstraintsVals, val) {
			return true
		}
	}

	return false
}

func contains(arr []string, obj string) bool {
	for _, val := range arr {
		if val == obj {
			return true
		}
	}

	return false
}

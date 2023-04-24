package check

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	"gopkg.in/yaml.v2"
)

type Controller interface {
	RunChecks(runner Runner, filter Predicate, skipIDMap map[string]bool) Summary
	RunChecksWithEnvs(runner Runner, filter Predicate, skipIDMap map[string]bool, envs []string) Summary
}

// Controls holds all controls to check for master nodes.
type Controls struct {
	ID              string   `yaml:"id" json:"id"`
	Text            string   `json:"text" yaml:"text"`
	Version         string   `json:"version"`
	DetectedVersion string   `json:"detected_version"`
	Type            NodeType `json:"node_type,omitempty"`
	Groups          []*Group `json:"tests" yaml:"groups"`
	Summary
	DefinedConstraints map[string][]string `json:"-"`
}

// Group is a collection of similar checks.
type Group struct {
	ID          string              `yaml:"id" json:"section"`
	Text        string              `json:"desc" yaml:"text"`
	Constraints map[string][]string `yaml:"constraints" json:"-"`
	Type        string              `yaml:"type" json:"type"`
	Checks      []*Check            `json:"results"`
	Pass        int                 `json:"pass"` // Tests with no type that passed
	Fail        int                 `json:"fail"` // Tests with no type that failed
	Warn        int                 `json:"warn"` // Tests of type manual won't be run and will be marked as Warn
	Info        int                 `json:"info"` // Tests of type skip won't be run and will be marked as Info
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

// NewControls instantiates a new Controls struct.
func NewControls(t NodeType, in []byte, detectedVersion string, definitions []string) (Controller, error) {
	c := new(Controls)

	err := yaml.Unmarshal(in, c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %s", err)
	}

	if t != "" && t != c.Type {
		return nil, fmt.Errorf("non-%s controls file specified", t)
	}
	c.DetectedVersion = detectedVersion

	if len(definitions) > 0 {
		c.DefinedConstraints = map[string][]string{}
		for _, val := range definitions {
			a := strings.Split(val, "=")

			// If its type 'category=value' for example 'platform=ubuntu'
			if len(a) == 2 && a[0] != "" && a[1] != "" {
				c.DefinedConstraints[a[0]] = append(c.DefinedConstraints[a[0]], a[1])
			} else {
				logging.GetLogger().Warn().Msgf("failed to parse defined constraint, %s", val)
			}
		}
	}

	return c, nil
}

func (controls *Controls) RunChecksWithEnvs(runner Runner, filter Predicate, skipIDMap map[string]bool, envs []string) Summary {
	var g []*Group
	m := make(map[string]*Group)
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Info = 0, 0, 0, 0

	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			if !filter(group, check) {
				continue
			}

			// Check if group and check has constraints
			if group.Constraints != nil {
				groupConstraintsOk := true
				for testConstraintKey, testConstraintVals := range group.Constraints {
					groupConstraintsOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, controls.DefinedConstraints)
					// If group constraints is not applied then skip test.
					if !groupConstraintsOk {
						check.Type = SKIP
					}
				}
			} else if check.Constraints != nil {
				checkConstraintsOk := true
				for testConstraintKey, testConstraintVals := range check.Constraints {
					checkConstraintsOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, controls.DefinedConstraints)
					// If check constraints is not applied then skip test.
					if !checkConstraintsOk {
						check.Type = SKIP
					}
				}
			}

			_, groupSkippedViaCmd := skipIDMap[group.ID]
			_, checkSkippedViaCmd := skipIDMap[check.ID]

			if group.Type == SKIP || groupSkippedViaCmd || checkSkippedViaCmd {
				check.Type = SKIP
			}

			state := runner.RunWithEnvs(check, envs)

			check.TestInfo = append(check.TestInfo, check.Remediation)

			// Check if we have already added this checks group.
			if v, ok := m[group.ID]; !ok {
				// Create a group with same info
				w := &Group{
					ID:     group.ID,
					Text:   group.Text,
					Checks: []*Check{},
				}

				// Add this check to the new group
				w.Checks = append(w.Checks, check)
				summarizeGroup(w, state)

				// Add to groups we have visited.
				m[w.ID] = w
				g = append(g, w)
			} else {
				v.Checks = append(v.Checks, check)
				summarizeGroup(v, state)
			}

			summarize(controls, state)
		}
	}

	controls.Groups = g
	return controls.Summary
}

// RunChecks runs the checks with the given Runner. Only checks for which the filter Predicate returns `true` will run.
func (controls *Controls) RunChecks(runner Runner, filter Predicate, skipIDMap map[string]bool) Summary {
	var g []*Group
	m := make(map[string]*Group)
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Info = 0, 0, 0, 0

	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			logging.GetLogger().Info().Msgf("Running check: %+v", check)
			if !filter(group, check) {
				continue
			}

			// Check if group and check has constraints
			if group.Constraints != nil {
				groupConstraintsOk := true
				for testConstraintKey, testConstraintVals := range group.Constraints {
					groupConstraintsOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, controls.DefinedConstraints)
					// If group constraints is not applied then skip test.
					if !groupConstraintsOk {
						check.Type = SKIP
					}
				}
			} else if check.Constraints != nil {
				checkConstraintsOk := true
				for testConstraintKey, testConstraintVals := range check.Constraints {
					checkConstraintsOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, controls.DefinedConstraints)
					// If check constraints is not applied then skip test.
					if !checkConstraintsOk {
						check.Type = SKIP
					}
				}
			}

			_, groupSkippedViaCmd := skipIDMap[group.ID]
			_, checkSkippedViaCmd := skipIDMap[check.ID]

			if group.Type == SKIP || groupSkippedViaCmd || checkSkippedViaCmd {
				check.Type = SKIP
			}

			state := runner.Run(check)

			check.TestInfo = append(check.TestInfo, check.Remediation)

			// Check if we have already added this checks group.
			if v, ok := m[group.ID]; !ok {
				// Create a group with same info
				w := &Group{
					ID:     group.ID,
					Text:   group.Text,
					Checks: []*Check{},
				}

				// Add this check to the new group
				w.Checks = append(w.Checks, check)
				summarizeGroup(w, state)

				// Add to groups we have visited.
				m[w.ID] = w
				g = append(g, w)
			} else {
				v.Checks = append(v.Checks, check)
				summarizeGroup(v, state)
			}

			summarize(controls, state)
		}
	}

	controls.Groups = g
	return controls.Summary
}

func summarize(controls *Controls, state State) {
	switch state {
	case PASS:
		controls.Summary.Pass++
	case FAIL:
		controls.Summary.Fail++
	case WARN:
		controls.Summary.Warn++
	case INFO:
		controls.Summary.Info++
	default:
		logging.GetLogger().Warn().Msgf("Unrecognized state %s", state)
	}
}

func summarizeGroup(group *Group, state State) {
	switch state {
	case PASS:
		group.Pass++
	case FAIL:
		group.Fail++
	case WARN:
		group.Warn++
	case INFO:
		group.Info++
	default:
		logging.GetLogger().Warn().Msgf("Unrecognized state %s", state)
	}
}

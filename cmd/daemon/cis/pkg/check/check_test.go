package check

import (
	"strings"
	"testing"
)

func TestCheck_Run(t *testing.T) {
	type TestCase struct {
		name     string
		check    Check
		Expected State
	}

	testCases := []TestCase{
		{name: "Manual check should WARN", check: Check{Type: MANUAL}, Expected: WARN},
		{name: "Skip check should INFO", check: Check{Type: "skip"}, Expected: INFO},
		{name: "Unscored check (with no type) should WARN on failure", check: Check{Scored: false}, Expected: WARN},
		{
			name: "Unscored check that pass should PASS",
			check: Check{
				Scored: false,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},

		{name: "Check with no tests should WARN", check: Check{Scored: true}, Expected: WARN},
		{name: "Scored check with empty tests should FAIL", check: Check{Scored: true, Tests: &tests{}}, Expected: FAIL},
		{
			name: "Scored check that doesn't pass should FAIL",
			check: Check{
				Scored: true,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  false,
				}}},
			},
			Expected: FAIL,
		},
		{
			name: "Scored checks that pass should PASS",
			check: Check{
				Scored: true,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.check.run()
			if testCase.check.State != testCase.Expected {
				t.Errorf("expected %s, actual %s", testCase.Expected, testCase.check.State)
			}
		})
	}
}

func Test_runAudit(t *testing.T) {
	type args struct {
		audit  string
		output string
	}
	tests := []struct {
		name   string
		args   args
		errMsg string
		output string
	}{
		{
			name: "run success",
			args: args{
				audit: "echo 'hello world'",
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run multiple lines script",
			args: args{
				audit: `
hello() {
  echo "hello world"
}

hello
`,
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run failed",
			args: args{
				audit: "unknown_command",
			},
			errMsg: "failed to run: \"unknown_command\", output: \"/bin/sh: ",
			output: "not found\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errMsg string
			output, err := runAudit(tt.args.audit)
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != "" && !strings.Contains(errMsg, tt.errMsg) {
				t.Errorf("name %s errMsg = %q, want %q", tt.name, errMsg, tt.errMsg)
			}
			if errMsg == "" && output != tt.output {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
			if errMsg != "" && !strings.Contains(output, tt.output) {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
		})
	}
}

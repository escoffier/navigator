package memshell

import (
	"reflect"
	"testing"
)

func TestReadYAML(t *testing.T) {
	// Assuming there's a valid test.yaml and an invalid test_invalid.yaml for testing
	validFilename := "../../../configs/daemon/memshell/Memory_Horse.yaml"
	// invalidFilename := "test_invalid.yaml"
	nonExistingFilename := "non_existing.yaml"

	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{"Valid file", validFilename, false},
		// {"Invalid file", invalidFilename, true},
		{"Non-existing file", nonExistingFilename, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadYAML(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseCmdline(t *testing.T) {
	envVars := map[string]string{
		"$TEST_VAR": "test_value",
		"$Filter":   "aaaaa\nbbbbbb\nccccc\ndddddd",
	}

	tests := []struct {
		name       string
		cmdline    string
		envVars    map[string]string
		wantResult string
		wantCmd    []string
	}{
		{"With existing env var", "echo $TEST_VAR", envVars, "", []string{"echo test_value"}},
		{"With non-existing env var", "echo $NON_EXISTING_VAR", envVars, "", []string{"echo $NON_EXISTING_VAR"}},
		{"Without env var", "echo 'Hello, world!'", envVars, "", []string{"echo 'Hello, world!'"}},
		{"Empty cmdline", "", envVars, "", nil},
		{"real rule", "mbean | grep \"j2eeType=Filter\" | grep -E \",name=[A-Za-z]+[0-9]{13},\"", envVars, "", []string{"mbean | grep \"j2eeType=Filter\" | grep -E \",name=[A-Za-z]+[0-9]{13},\""}},
		{"only result", "$Filter = \"sc *.Filter\" | grep \"org.apache.coyote\"", envVars, "$Filter", []string{"\"sc *.Filter\" | grep \"org.apache.coyote\""}},
		{"mix 1", "$Loader = \"sc -d $Filter\" | grep -E '\\+-org\\.apache\\.jsp\\..+_jsp\\$X@[0-9a-fA-F]{8}'", envVars, "$Loader", []string{
			"\"sc -d aaaaa\" | grep -E '\\+-org\\.apache\\.jsp\\..+_jsp\\$X@[0-9a-fA-F]{8}'",
			"\"sc -d bbbbbb\" | grep -E '\\+-org\\.apache\\.jsp\\..+_jsp\\$X@[0-9a-fA-F]{8}'",
			"\"sc -d ccccc\" | grep -E '\\+-org\\.apache\\.jsp\\..+_jsp\\$X@[0-9a-fA-F]{8}'",
			"\"sc -d dddddd\" | grep -E '\\+-org\\.apache\\.jsp\\..+_jsp\\$X@[0-9a-fA-F]{8}'",
		}},
		{"mix 2", "$RESULT = classloader | grep \"_jsp$U\"", envVars, "$RESULT", []string{
			"classloader | grep \"_jsp$U\"",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotCmd := ParseCmdline(tt.cmdline, tt.envVars)
			if gotResult != tt.wantResult {
				t.Errorf("ParseCmdline() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
			if !reflect.DeepEqual(gotCmd, tt.wantCmd) {
				t.Errorf("ParseCmdline() gotCmd = %v, want %v", gotCmd, tt.wantCmd)
			}
		})
	}
}

package scannerUtils

import (
	"encoding/json"
	"io"
	"os"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

type Sensitive struct {
	Description string `json:"description"`
	SecretType  string `json:"secret_type"`
	Value       string `json:"value"`
}

func GetSensitiveRuleFromFile(path string) ([]Sensitive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data := make([]Sensitive, 0)

	byteValue, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func MainCluster() bool {
	if os.Getenv("IS_MAIN_CLUSTER") != consts.TrueString {
		logging.Get().Info().Msg("not in main cluster")
		return false
	}

	logging.Get().Info().Msg("in main cluster")
	return true
}

func CommonFilter(fi os.FileInfo) bool {
	mod := fi.Mode()
	if mod&os.ModeSymlink != 0 {
		return false
	}
	if mod&os.ModeDir != 0 {
		return false
	}
	if mod&os.ModeDevice != 0 {
		return false
	}
	if mod&os.ModeNamedPipe != 0 {
		return false
	}
	if mod&os.ModeSymlink != 0 {
		return false
	}
	if mod&os.ModeSocket != 0 {
		return false
	}
	if mod&os.ModeSocket != 0 {
		return false
	}
	// if fi.Size() == 0 {
	// 	return false
	// }
	// if fi.IsDir() {
	// 	return false
	// }

	return true
}

type FileFilter func(fi os.FileInfo) bool

package scannerUtils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"github.com/docker/distribution/manifest/schema2"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
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

func GetSoftVersion() string {
	ver := os.Getenv("SOFT_VERSION")
	if ver == "" {
		ver = "latest"
	}
	return ver
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

func ManifestV2Digest(m *schema2.DeserializedManifest) string {
	// caculate image digest
	data, err := m.MarshalJSON()
	if err != nil {
		return ""
	}
	dig, _, err := SHA256(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	return dig.String()
}

func SHA256(r io.Reader) (warehouse.Hash, int64, error) {
	hasher := sha256.New()
	n, err := io.Copy(hasher, r)
	if err != nil {
		return warehouse.Hash{}, 0, err
	}
	return warehouse.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size()))),
	}, n, nil
}

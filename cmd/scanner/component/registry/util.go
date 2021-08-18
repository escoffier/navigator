package registry

import (
	"bytes"
	"github.com/docker/distribution/manifest/schema2"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func RegistryClientLog(format string, args ...interface{}) {
	logging.GetLogger().Trace().Msgf(format, args...)
}

func ManifestV2Digest(m *schema2.DeserializedManifest) (string, error) {
	// caculate image digest
	data, err := m.MarshalJSON()
	if err != nil {
		return "", err
	}
	digest, _, err := SHA256(bytes.NewReader(data))

	return digest.String(), err
}

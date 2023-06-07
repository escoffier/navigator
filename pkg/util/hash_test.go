package util

import (
	"crypto"
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func TestHash(t *testing.T) {
	origin := "test_string"

	t.Log("MD5: ", MD5(origin))
	t.Log("SHA1: ", SHA1(origin))
	t.Log("SHA256: ", SHA256(origin))
	t.Log(Hash(crypto.SHA512, origin))
}

func TestHashFromFile(t *testing.T) {
	str, err := Md5FromFile("/trivy/trivy.db")
	if err != nil {
		logging.GetLogger().Err(err).Msg("Md5FromFile error")
		return
	}
	logging.GetLogger().Info().Msgf("str :%v", str)
}

package util

import (
	"crypto"
	"testing"
)

func TestHash(t *testing.T) {
	origin := "test_string"

	t.Log("MD5: ", MD5(origin))
	t.Log("SHA1: ", SHA1(origin))
	t.Log("SHA256: ", SHA256(origin))
	t.Log(Hash(crypto.SHA512, origin))
}

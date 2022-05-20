package util

import (
	"crypto"
	"encoding/hex"
	"fmt"
)

func MD5(str string) []byte {
	hashed, _ := Hash(crypto.MD5, str)
	return hashed
}

func MD5Hex(str string) string {
	hashed, _ := HashHex(crypto.MD5, str)
	return hashed
}

func SHA1(str string) []byte {
	hashed, _ := Hash(crypto.SHA1, str)
	return hashed
}

func SHA1Hex(str string) string {
	hashed, _ := HashHex(crypto.SHA1, str)
	return hashed
}

func SHA256(str string) []byte {
	hashed, _ := Hash(crypto.SHA256, str)
	return hashed
}

func SHA256Hex(str string) string {
	hashed, _ := HashHex(crypto.SHA256, str)
	return hashed
}

func Hash(hash crypto.Hash, str string) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("invilid hash")
	}

	h := hash.New()
	h.Write([]byte(str))
	return h.Sum(nil), nil
}

func HashHex(h crypto.Hash, str string) (string, error) {
	hashed, err := Hash(h, str)
	if err != nil {
		return "", nil
	}

	return hex.EncodeToString(hashed), nil
}

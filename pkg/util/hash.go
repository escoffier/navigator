package util

import (
	"crypto"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"gitlab.com/security-rd/go-pkg/logging"
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

func Md5FromFile(path string) (string, error) {
	fs, err := os.Open(path)
	if err != nil {
		logging.Get().Err(err).Msg("open path error")
		return "", err
	}
	originMd5 := md5.New()
	_, err = io.Copy(originMd5, fs)
	if err != nil {
		logging.Get().Err(err).Msg("get file hash error")
		return "", err
	}
	originMd5Str := hex.EncodeToString(originMd5.Sum(nil))
	return originMd5Str, nil
}

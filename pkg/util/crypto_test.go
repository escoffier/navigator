package util

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestAesDecryptCBC(t *testing.T) {
	origData := []byte("test aes cbc") // 待加密的数据
	key := []byte("SBxOPvtkkVkSWNCt")  // 加密的密钥
	t.Log("原文：", string(origData))

	encrypted, err := AesEncryptCBC(origData, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("密文(hex)：", hex.EncodeToString(encrypted))
	t.Log("密文(base64)：", base64.StdEncoding.EncodeToString(encrypted))
	decrypted, err := AesDecryptCBC(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("解密结果：", string(decrypted), err)

}

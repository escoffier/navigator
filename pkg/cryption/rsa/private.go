package rsa

import (
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

// Private 使用rsa私钥操作数据
type Private struct {
	privateKey *stdrsa.PrivateKey
}

// NewPrivateWithBytes 通过私钥的切片构造 *Private 对象
func NewPrivateWithBytes(privateKey []byte) (*Private, error) {
	block, _ := pem.Decode(privateKey)
	privateKeyInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse private key failed")
	}

	return &Private{privateKey: privateKeyInterface}, nil
}

// NewPrivateWithReader 通过一个reader对象构造 *Private 对象
func NewPrivateWithReader(reader io.Reader) (*Private, error) {
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, errors.Wrap(err, "read private key failed")
	}

	return NewPrivateWithBytes(data)
}

// NewPrivateWithPrivateKey 通过一个PrivateKey对象构造 *Private 对象
func NewPrivateWithPrivateKey(privateKey *stdrsa.PrivateKey) (*Private, error) {
	return &Private{privateKey: privateKey}, nil
}

// NewPrivateWithFile 通过一个文件路径构造 *Private 对象
func NewPrivateWithFile(file string) (*Private, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrapf(err, "create Private failed because open file:<%s> failed", file)
	}

	defer func() { _ = f.Close() }()

	return NewPrivateWithReader(f)
}

func (p *Private) Decrypt(cipherText []byte) ([]byte, error) {
	plainText, err := stdrsa.DecryptPKCS1v15(rand.Reader, p.privateKey, cipherText)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt failed by private key")
	}

	return plainText, nil
}

func (p *Private) Sign(data []byte) ([]byte, error) {
	msgHashSum, err := Sha256(data)
	if err != nil {
		return nil, errors.Wrapf(err, "get hash sum failed when sign, data: %s", data)
	}
	signature, err := stdrsa.SignPSS(rand.Reader, p.privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "sign failed, data: %s", data)
	}

	return signature, nil
}

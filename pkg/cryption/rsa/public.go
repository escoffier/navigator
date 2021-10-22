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

type Public struct {
	publicKey *stdrsa.PublicKey
}

// NewPublicWithBytes 通过私钥的切片构造 *Public 对象
func NewPublicWithBytes(privateKey []byte) (*Public, error) {
	block, _ := pem.Decode(privateKey)
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse private key failed")
	}

	key, ok := publicKeyInterface.(*stdrsa.PublicKey)
	if !ok {
		return nil, errors.Wrap(err, "it is not a rsa public key")
	}

	return &Public{publicKey: key}, nil
}

// NewPublicWithReader 通过一个reader对象构造 *Public 对象
func NewPublicWithReader(reader io.Reader) (*Public, error) {
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, errors.Wrap(err, "read private key failed")
	}

	return NewPublicWithBytes(data)
}

// NewPublicWithPublicKey 通过一个PublicKey对象构造 *Public 对象
func NewPublicWithPublicKey(publicKey *stdrsa.PublicKey) (*Public, error) {
	return &Public{publicKey: publicKey}, nil
}

// NewPublicWithFile 通过一个文件路径构造 *Public 对象
func NewPublicWithFile(file string) (*Public, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrapf(err, "create Public failed because open file:<%s> failed", file)
	}

	defer func() { _ = f.Close() }()

	return NewPublicWithReader(f)
}

func (p *Public) Encrypt(data []byte) ([]byte, error) {
	cipherText, err := stdrsa.EncryptPKCS1v15(rand.Reader, p.publicKey, data)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt failed by public key")
	}

	return cipherText, nil
}

func (p *Public) VerifySign(data, signature []byte) error {
	msgHashSum, err := Sha256(data)
	if err != nil {
		return errors.Wrapf(err, "get hash sum failed when verify sign, data: %s, signature: %s", data, signature)
	}

	err = stdrsa.VerifyPSS(p.publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		return errors.Wrapf(err, "verify sign failed, data: %s, signature: %s", data, signature)
	}

	return nil
}

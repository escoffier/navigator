package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

type Hash struct {
	// Algorithm holds the algorithm used to compute the hash.
	Algorithm string

	// Hex holds the hex portion of the content hash.
	Hex string
}

func (h Hash) String() string {
	return fmt.Sprintf("%s:%s", h.Algorithm, h.Hex)
}

func SHA256(r io.Reader) (Hash, int64, error) {
	hasher := sha256.New()
	n, err := io.Copy(hasher, r)
	if err != nil {
		return Hash{}, 0, err
	}
	return Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size()))),
	}, n, nil
}

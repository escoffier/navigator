package util

import (
	"encoding/hex"
	"hash/fnv"
	"strings"

	uuid "github.com/satori/go.uuid"
)

func GenerateUUID(strs ...string) uint32 {
	s := strings.Join(strs, "/")
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

func GenerateUUIDHex() string {
	return hex.EncodeToString(uuid.NewV4().Bytes())
}

func GenerateUUID64(strs ...string) uint64 {
	s := strings.Join(strs, "/")
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

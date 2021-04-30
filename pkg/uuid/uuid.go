package uuid

import (
	"crypto/rand"
	"encoding/binary"
	"go.uber.org/atomic"
	"math"
	"time"
)

type Generator struct {
	processRand uint16
	counter     *atomic.Uint32
}

func NewGenerator() (*Generator, error) {
	var randBytes [2]byte
	_, err := rand.Read(randBytes[:])
	if err != nil {
		return nil, err
	}

	return &Generator{
		counter:     atomic.NewUint32(0),
		processRand: binary.BigEndian.Uint16(randBytes[:]),
	}, nil
}

// Generate UUID
// NOTE: If functions are called more than math.MaxUint16 times in one second, it will generate duplicate ID
func (g *Generator) GenerateUUID() uint64 {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:4], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint16(buf[4:6], g.processRand)
	binary.BigEndian.PutUint16(buf[6:], uint16(g.counter.Inc()%uint32(math.MaxUint16)))
	return binary.BigEndian.Uint64(buf[:])
}

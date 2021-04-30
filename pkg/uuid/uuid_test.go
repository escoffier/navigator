package uuid

import (
	"github.com/stretchr/testify/assert"
	"math"
	"sync"
	"testing"
)

func TestGenerator_GenerateUUID(t *testing.T) {
	generator, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(generator.processRand)

	t.Log(generator.GenerateUUID())

	var hash = make(map[uint64]struct{})
	var lock sync.Mutex
	var wg sync.WaitGroup
	wg.Add(math.MaxUint16)
	for i := 0; i < math.MaxUint16; i++ {
		go func() {
			lock.Lock()
			hash[generator.GenerateUUID()] = struct{}{}
			lock.Unlock()
			wg.Done()
		}()
	}

	wg.Wait()
	assert.Equal(t, math.MaxUint16, len(hash))
}

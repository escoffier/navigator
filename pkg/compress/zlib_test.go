package compress

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZlib(t *testing.T) {
	var s = `愿中国青年都摆脱冷气，只是向上走，不必听自暴自弃者流的话。
能做事的做事，能发声的发声。
有一分热，发一分光。
就令萤火一般，也可以在黑暗里发一点光。
——不必等候炬火
此后如竟没有炬火，我便是唯一的光。`
	t.Logf("raw string len: %d", len(s))

	compressStr, err := ZlipCompress([]byte(s))
	assert.Nil(t, err)
	t.Logf("compress string len: %d", len(compressStr))

	rawStr, err := ZlipDecompress(compressStr)
	assert.Nil(t, err)
	assert.Equal(t, s, string(rawStr))
}

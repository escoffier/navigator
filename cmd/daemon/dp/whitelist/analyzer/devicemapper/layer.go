package devicemapper

import (
	"github.com/docker/docker/api/types"
	"github.com/opencontainers/go-digest"
)

type DiffID digest.Digest

// String returns a string rendition of a layer DiffID
func (diffID DiffID) String() string {
	return string(diffID)
}

// ChainID is the content-addressable ID of a layer.
type ChainID digest.Digest

// String returns a string rendition of a layer ID
func (id ChainID) String() string {
	return string(id)
}

// CreateChainID returns ID for a layerDigest slice
func CreateChainID(dgsts []DiffID) ChainID {
	return createChainIDFromParent("", dgsts...)
}

func createChainIDFromParent(parent ChainID, dgsts ...DiffID) ChainID {
	if len(dgsts) == 0 {
		return parent
	}
	if parent == "" {
		return createChainIDFromParent(ChainID(dgsts[0]), dgsts[1:]...)
	}
	// H = "H(n-1) SHA256(n)"
	dgst := digest.FromBytes([]byte(string(parent) + " " + string(dgsts[0])))
	return createChainIDFromParent(ChainID(dgst), dgsts[1:]...)
}

func ApiTypeToRootFS(rootfs types.RootFS) []DiffID {
	var layers []DiffID
	for _, l := range rootfs.Layers {
		layers = append(layers, DiffID(l))
	}
	return layers
}

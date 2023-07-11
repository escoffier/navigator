package cache

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/security-rd/go-pkg/logging"
	"sync"
	"time"
)

// ImageResultCache cache all clusters image scanned flag, image digest as key
type ImageResultCache struct {
	recvResult     chan imagesec.ScanResultWithVersion
	scannedResults map[string]imagesec.ScanResultWithVersion
	lock           sync.RWMutex
}

const (
	defaultChanLength     = 1000
	defaultEnqueueTimeout = 3
)

var (
	instance *ImageResultCache
)

func init() {
	instance = &ImageResultCache{
		scannedResults: make(map[string]imagesec.ScanResultWithVersion),
		recvResult:     make(chan imagesec.ScanResultWithVersion, defaultChanLength),
	}
}

func GetResultCache() *ImageResultCache {
	return instance
}

func (i *ImageResultCache) Type() consts.ServiceType {
	return consts.TypeServiceImageResultCache
}

func (i *ImageResultCache) Run() error {
	for {
		// read result
		result := <-i.recvResult
		logging.Get().Info().Str("digest", result.Digest).Msg("recv image scanned result")

		// record to map
		i.saveResult(result)

		// todo: dump to local file
	}
}

func (i *ImageResultCache) saveResult(result imagesec.ScanResultWithVersion) {
	i.lock.Lock()
	defer i.lock.Unlock()

	// todo: support local build images which do not have digest
	if len(result.Digest) == 0 {
		return
	}
	i.scannedResults[result.Digest] = result
}

func (i *ImageResultCache) EnqueueResult(result imagesec.ScanResultWithVersion) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultEnqueueTimeout*time.Second)
	defer cancel()

	select {
	case <-ctx.Done():
		return fmt.Errorf("enqueue err:%v", ctx.Err())
	case i.recvResult <- result:
		return nil
	}
}

func (i *ImageResultCache) CheckScanned(digest string) bool {
	i.lock.Lock()
	defer i.lock.Unlock()
	_, ok := i.scannedResults[digest]
	if !ok {
		// not scanned
		return false
	}

	// todo: compare local vuln db and scanned result vuln db
	return true
}

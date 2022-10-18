package fs

import (
	"gitlab.com/security-rd/go-pkg/logging"
	"sync"
)

type ImageFsCache struct {
	imageWhiteListCache map[string]map[string]string // used for cache, overlay2-path->map[filename]hash
	cacheLock           sync.Mutex
	hitCount            int // cache hit count
	imageDirCount       int // statistics
}

var (
	instance *ImageFsCache
)

func init() {
	instance = &ImageFsCache{
		imageWhiteListCache: make(map[string]map[string]string),
	}
}

func GetImageFsCache() *ImageFsCache {
	return instance
}

func (i *ImageFsCache) HitCache(localPath string, whiteList map[string]string) bool {
	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()
	i.imageDirCount++
	if _, ok := i.imageWhiteListCache[localPath]; ok {
		logging.Get().Trace().Msgf("image dir:%v already in white list", localPath)
		i.hitCount++
		for k, v1 := range i.imageWhiteListCache[localPath] {
			whiteList[k] = v1
		}
		i.cacheLock.Unlock()
		return true
	}
	return false
}

func (i *ImageFsCache) CacheResult(localPath string, whiteList map[string]string) {
	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()
	if i.imageWhiteListCache[localPath] == nil {
		i.imageWhiteListCache[localPath] = make(map[string]string)
	}
	i.imageWhiteListCache[localPath] = whiteList
}

func (i *ImageFsCache) HitCount() int {
	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()
	return i.hitCount
}

func (i *ImageFsCache) TotalCheckDirNum() int {
	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()
	return i.imageDirCount
}

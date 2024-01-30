package imagecache

import (
	"fmt"
	"sync"
)

type LayerQueue struct {
	WG     *sync.RWMutex
	Layers map[string]*LayerInfo
}

func NewLayerQueue() *LayerQueue {
	s := &LayerQueue{
		WG:     &sync.RWMutex{},
		Layers: make(map[string]*LayerInfo),
	}
	return s
}

func (vi *LayerQueue) Set(lay *LayerInfo) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	if lay == nil {
		return
	}
	vi.Layers[lay.digest] = lay
}

func (vi *LayerQueue) Pulled(digest string) bool {
	vi.WG.RLock()
	defer vi.WG.RUnlock()
	lay, b := vi.Layers[digest]
	if !b {
		return b
	}
	return lay.status == LayerPulled
}

func (vi *LayerQueue) Get(dig string) (*LayerInfo, bool) {
	vi.WG.RLock()
	defer vi.WG.RUnlock()
	li, ok := vi.Layers[dig]
	lar := &LayerInfo{
		digest:     li.digest,
		repository: li.repository,
		refCount:   li.refCount,
		url:        li.url,
		layerURL:   li.layerURL,
		status:     li.status,
		flag:       li.flag,
		username:   li.username,
		password:   li.password,
		skipTLS:    li.skipTLS,
	}

	return lar, ok
}

func (vi *LayerQueue) Exist(dig string) bool {
	vi.WG.RLock()
	defer vi.WG.RUnlock()
	lay, ok := vi.Layers[dig]
	return ok && lay != nil
}

func (vi *LayerQueue) Delete(dig string) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	delete(vi.Layers, dig)
}

func (vi *LayerQueue) NeedDelete(dig string) bool {
	vi.WG.RLock()
	defer vi.WG.RUnlock()
	lay, ok := vi.Layers[dig]
	return ok && lay != nil && lay.refCount <= 0
}

func (vi *LayerQueue) Inc(dig string) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	li, ok := vi.Layers[dig]
	if ok && li != nil {
		li.refCount++
		return
	}
}

func (vi *LayerQueue) Dec(dig string) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	li, ok := vi.Layers[dig]
	if ok {
		li.refCount--
		return
	}
}

func (vi *LayerQueue) GetNeedPullLayer() LayerInfo {
	vi.WG.Lock()
	defer vi.WG.Unlock()

	for k, v := range vi.Layers {
		if v.status == LayerNotPull {
			vi.Layers[k].status = LayerPulling
			lay := LayerInfo{
				digest:     v.digest,
				repository: v.repository,
				refCount:   v.refCount,
				url:        v.url,
				layerURL:   v.layerURL,
				status:     LayerPulling,
				flag:       v.flag,
				username:   v.username,
				password:   v.password,
				skipTLS:    v.skipTLS,
			}
			return lay
		}
	}
	return LayerInfo{}
}

func (vi *LayerQueue) UpdateTask(digest, layerURL string, status int) error {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	lay, ok := vi.Layers[digest]
	if !ok || lay == nil {
		return fmt.Errorf("not found layer %s", digest)
	}
	vi.Layers[digest].status = status
	vi.Layers[digest].layerURL = layerURL

	return nil
}

func (vi *LayerQueue) NotifyLayerPulled(digest string) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	lay, ok := vi.Layers[digest]
	if ok && lay != nil {
		lay.status = LayerPulled
	}
}

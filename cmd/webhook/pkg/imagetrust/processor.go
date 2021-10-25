package imagetrust

import (
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"sync"
)

var (
	imageDigest *ImageDigestMap
	irlOnce     sync.Once
)

type ImageDigestMap struct {
	DigestImage map[string]string
	sync.RWMutex
}

func InitImageDigestMap() {
	irlOnce.Do(func() {
		imageDigest = &ImageDigestMap{
			DigestImage: make(map[string]string),
			RWMutex:     sync.RWMutex{},
		}
	})
}

func GetImageDigestMap() (*ImageDigestMap, bool) {
	return imageDigest, imageDigest != nil
}

func (d *ImageDigestMap) add(k, v string) {
	d.Lock()
	defer d.Unlock()
	d.DigestImage[k] = v
}

func (d *ImageDigestMap) get(k string) string {
	d.RLock()
	defer d.RUnlock()
	return d.DigestImage[k]
}

func Register() {
	v := Validator{}
	processors.Registry(v.Name(), v)

	m := Mutator{}
	processors.Registry(m.Name(), m)
}

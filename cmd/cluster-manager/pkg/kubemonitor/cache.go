package kubemonitor

import (
	"bytes"
	"sync"
	"time"

	pkg "gitlab.com/piccolo_su/vegeta/pkg/kubemonitor"
)

type DupCache struct {
	data   *sync.Map // string(id) -> timestamp
	ttlSec int64
}

func newDupCache(ttl time.Duration) *DupCache {
	c := &DupCache{
		data:   new(sync.Map),
		ttlSec: int64(ttl.Seconds()),
	}
	c.asyncUpdate()

	return c
}

func getEvtID(evt pkg.KubeMonitorEvent, ruleName string) []byte {
	var b bytes.Buffer
	b.WriteString(ruleName)
	b.WriteByte(',')
	b.WriteString(evt.Cluster)
	b.WriteByte('/')
	b.WriteString(evt.GetTargetNamespace())
	b.WriteByte('/')
	b.WriteString(evt.GetTargetName())
	return b.Bytes()
}
func (c *DupCache) addEvent(evt pkg.KubeMonitorEvent, ruleName string) {
	id := string(getEvtID(evt, ruleName))

	now := time.Now()
	c.data.Store(id, now.Unix())
}

func (c *DupCache) checkDuplicate(evt pkg.KubeMonitorEvent, ruleName string) bool {
	id := string(getEvtID(evt, ruleName))

	o, ok := c.data.Load(id)
	if ok {
		stamp := o.(int64)
		now := time.Now()
		return now.Unix()-stamp < c.ttlSec
	}
	return false
}

func (c *DupCache) asyncUpdate() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case now := <-ticker.C:
				nowstamp := now.Unix()
				toDelete := make([]string, 0, 5)
				c.data.Range(func(k, v interface{}) bool {
					createdStamp := v.(int64)
					if nowstamp-createdStamp > c.ttlSec {
						toDelete = append(toDelete, k.(string))
					}
					return true
				})

				for _, id := range toDelete {
					c.data.Delete(id)
				}
			}
		}
	}()
}

package kubemonitor

import (
	"sync"
	"time"
)

// shared mem storage for each cluster
type MemStorage struct {
	clusterName       string
	riskyRoles        *sync.Map // string(namespace/name) -> createdTimestamp(time.Time)
	riskyClusterRoles *sync.Map // string(name) -> struct{}
}

func newMemStorage(clusterName string) *MemStorage {
	return &MemStorage{
		clusterName:       clusterName,
		riskyRoles:        new(sync.Map),
		riskyClusterRoles: new(sync.Map),
	}
}
func (s *MemStorage) SetRoleRisky(name, namespace string) error {
	now := time.Now()
	s.riskyRoles.Store(getKeyFromNameAndNS(name, namespace), now)
	return nil
}
func (s *MemStorage) SetClusterRoleRisky(name string) error {
	now := time.Now()
	s.riskyClusterRoles.Store(name, now)
	return nil
}
func (s *MemStorage) RemoveRole(name, namespace string) (existed bool, err error) {
	_, existed = s.riskyRoles.LoadAndDelete(getKeyFromNameAndNS(name, namespace))
	return
}
func (s *MemStorage) RemoveClusterRole(name string) (existed bool, err error) {
	_, existed = s.riskyClusterRoles.LoadAndDelete(name)
	return
}
func (s *MemStorage) IsRoleRisky(name, namespace string) bool {
	_, existed := s.riskyRoles.Load(getKeyFromNameAndNS(name, namespace))
	return existed
}
func (s *MemStorage) IsClusterRoleRisky(name string) bool {
	_, existed := s.riskyClusterRoles.Load(name)
	return existed
}

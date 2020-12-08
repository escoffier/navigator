package api

import (
	"sync"

	"github.com/patrickmn/go-cache"
)

// TODO : complete it

type UserRoleItem struct {
	UserName    string
	RoleNameSet map[string]struct{}
	mu          sync.RWMutex
}

type RoleAccessItem struct {
	RoleName      string
	AccessNameSet map[string]struct{}
	mu            sync.RWMutex
}

func RBACAddRoletoUser(rc *cache.Cache, userName, roleName string) {
	inf, ok := rc.Get(userName)

	if ok {
		userRole, ok1 := inf.(*UserRoleItem)
		if ok1 {
			userRole.mu.Lock()
			defer userRole.mu.Unlock()
			userRole.RoleNameSet[roleName] = struct{}{}
			rc.Set(userName, userRole, cache.NoExpiration)

			return
		}
	}

	userRole := UserRoleItem{
		UserName:    userName,
		RoleNameSet: map[string]struct{}{},
	}
	userRole.mu.Lock()
	defer userRole.mu.Unlock()
	userRole.RoleNameSet[roleName] = struct{}{}
	rc.Set(userName, &userRole, cache.NoExpiration)
}

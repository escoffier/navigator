package util

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	CtxUserKey = "ctx_userinfo"
)

func GetUserFromContext(ctx context.Context) (*model.User, bool) {
	val := ctx.Value(CtxUserKey)
	if val == nil {
		return nil, false
	}
	uinfo, ok := val.(*model.User)
	return uinfo, ok
}

func GetUsernameFromContext(ctx context.Context) string {
	user, ok := GetUserFromContext(ctx)
	if ok && user != nil {
		return user.UserName
	}
	return ""
}

package util

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	CtxUserSessionKey = "ctx_user_session"
)

func GetSessionFromContext(ctx context.Context) (*model.UserSession, bool) {
	val := ctx.Value(CtxUserSessionKey)
	if val == nil {
		return nil, false
	}
	userSession, ok := val.(*model.UserSession)
	return userSession, ok
}

func GetUsernameFromContext(ctx context.Context) string {
	userSession, ok := GetSessionFromContext(ctx)
	if ok && userSession != nil {
		return userSession.Username
	}
	return ""
}

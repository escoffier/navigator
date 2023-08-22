package request

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/token"
)

type ctxKey string

const (
	ctxUserSessionKey ctxKey = "ctx_user_session"
)

func WithSession(ctx context.Context, payload token.Payload) context.Context {
	if ctx == nil {
		ctx = context.TODO()
	}

	return context.WithValue(ctx, ctxUserSessionKey, payload)
}

func GetSessionFromContext(ctx context.Context) (token.Payload, bool) {
	val := ctx.Value(ctxUserSessionKey)
	if val == nil {
		return token.Payload{}, false
	}
	userSession, ok := val.(token.Payload)
	return userSession, ok
}

func GetUsernameFromContext(ctx context.Context) string {
	userSession, ok := GetSessionFromContext(ctx)
	if ok {
		return userSession.Username
	}
	return ""
}

func GetAccountFromContext(ctx context.Context) string {
	userSession, ok := GetSessionFromContext(ctx)
	if ok {
		return userSession.Account
	}
	return ""
}

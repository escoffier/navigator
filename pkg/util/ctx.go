package util

import "context"

const (
	CtxKeyUser = "_username"
)

func GetUserFromContext(ctx context.Context) string {
	val := ctx.Value(CtxKeyUser)
	if val == nil {
		return ""
	}
	return val.(string)
}

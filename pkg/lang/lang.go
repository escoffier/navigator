package lang

import (
	"context"
	"net/http"
)

type LanguageKeyType string
type LanguageType string

const (
	LanguageCtxKey LanguageKeyType = "lang"
	LanguageEN     LanguageType    = "en"
	LanguageZH     LanguageType    = "zh"
)

func Language(ctx context.Context) LanguageType {
	l, ok := ctx.Value(LanguageCtxKey).(LanguageType)
	if !ok {
		return LanguageEN
	}
	return LanguageType(l)
}

func AcceptLanguageMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := withLanguage(r.Context(), r)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func isValid(langString string) bool {
	if langString != string(LanguageEN) && langString != string(LanguageZH) {
		return false
	}
	return true
}

func withLanguage(ctx context.Context, r *http.Request) context.Context {
	languageKey := r.Header.Get("Accept-Language")

	if !isValid(languageKey) {
		languageKey = string(LanguageEN)
	}

	return context.WithValue(ctx, LanguageCtxKey, LanguageType(languageKey))
}

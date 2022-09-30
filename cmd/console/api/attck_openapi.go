package api

import (
	"net/http"

	"github.com/go-chi/chi"
)

func (a *api) ATTCKOpenAPI() func(chi.Router) {
	return func(r chi.Router) {
		//r.Put("/conf", a.updateATTCKConf())
		r.Get("/ruleList", a.getATTCKRuleList())
		r.Post("/ruleSwitch", a.updateRuleSwitch())
	}
}

func (a *api) getATTCKRuleListOpenAPI() http.HandlerFunc {
	return a.getATTCKRuleList()
}

func (a *api) updateRuleSwitchOpenAPI() http.HandlerFunc {
	return a.updateRuleSwitch()
}

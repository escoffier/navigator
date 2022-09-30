package api

import (
	"net/http"

	"github.com/go-chi/chi"
)

func (a *api) processingCenterOpenAPI() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/record", a.addProcessingRecordOpenAPI())
		r.Get("/record", a.getProcessingRecords())
		r.Post("/record/status", a.updateProcessingRecordStatus())
		r.Post("/record/action", a.addProcessingAction())
		r.Get("/record/detail", a.getProcessingDetail())
	}
}

func (a *api) addProcessingRecordOpenAPI() http.HandlerFunc {
	return a.addProcessingRecord()
}

func (a *api) getProcessingRecordsOpenAPI() http.HandlerFunc {
	return a.getProcessingRecords()
}

func (a *api) updateProcessingRecordStatusOpenAPI() http.HandlerFunc {
	return a.updateProcessingRecordStatus()
}

func (a *api) addProcessingActionOpenAPI() http.HandlerFunc {
	return a.addProcessingAction()
}

func (a *api) getProcessingDetailOpenAPI() http.HandlerFunc {
	return a.getProcessingDetail()
}

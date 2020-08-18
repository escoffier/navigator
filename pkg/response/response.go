package response

import (
	"encoding/json"
	"net/http"
)

// Bad returns 400
func Bad(w http.ResponseWriter, msg string) {
	Respond(w, http.StatusBadRequest, HTTPError{
		Status: "failed",
		Error:  msg,
	})
}

// InternalError returns 500
func InternalError(w http.ResponseWriter, msg string) {
	Respond(w, http.StatusInternalServerError, HTTPError{
		Status: "failed",
		Error:  msg,
	})
}

// Unauthorized returns 401
func Unauthorized(w http.ResponseWriter, redirectURL string) {
	w.Header().Set("Location", redirectURL)
	Respond(w, http.StatusUnauthorized, HTTPRedirectError{
		HTTPError: HTTPError{
			Status: "failed",
			Error:  "unauthorized",
		},
		Redirect: redirectURL,
	})
}

// Ok write 200 response with payload in JSON format
func Ok(w http.ResponseWriter, payload interface{}) {
	Respond(w, http.StatusOK, payload)
}

// Respond setups the response correctly for HTTP requests
func Respond(w http.ResponseWriter, code int, payload interface{}) {
	if payload == nil {
		payload = EmptyResponse{Status: "ok"}
	}
	response, err := json.Marshal(payload)
	if err != nil {
		InternalError(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err = w.Write(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

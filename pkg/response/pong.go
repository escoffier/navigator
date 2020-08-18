// Package response defines many convenient methods to send a response for http requests
package response

import (
	"net/http"
)

// Pong returns "pong" to http
func Pong(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("pong"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

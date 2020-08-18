package response

// EmptyResponse only has status: ok
type EmptyResponse struct {
	Status string `json:"status"`
}

// HTTPError tells the status and error
type HTTPError struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

// HTTPRedirectError is an HTTPError with a redirect path
type HTTPRedirectError struct {
	HTTPError
	Redirect string `json:"redirect"`
}

package response

// Implements modified Google JSON styleguide
// https://google.github.io/styleguide/jsoncstyleguide.xml

// EmptyResponse only has status: ok
type EmptyResponse struct {
	Status string `json:"status"`
}

type HTTPEnvelope struct {
	ApiVersion string     `json:"apiVersion"`
	Data       *HTTPData  `json:"data,omitempty"`
	Error      *HTTPError `json:"error,omitempty"`
	// EnevlopeError is a special field to communicate any errors when using Functional Options pattern in response.go
	// It's not sent to the client.
	EnvelopeError string `json:"-"`
}

type HTTPData struct {
	Kind             string      `json:"kind,omitempty"`
	Etag             string      `json:"etag,omitempty"`
	Lang             string      `json:"lang,omitempty"`
	Updated          string      `json:"updated,omitempty"`
	Deleted          bool        `json:"deleted,omitempty"`
	CurrentItemCount bool        `json:"currentItemCount,omitempty"`
	ItemsPerPage     int64       `json:"itemsPerPage,omitempty"`
	StartIndex       int64       `json:"startIndex,omitempty"`
	TotalItems       int64       `json:"totalItems,omitempty"`
	PageIndex        int64       `json:"pageIndex,omitempty"`
	TotalPages       int64       `json:"totalPages,omitempty"`
	Items            interface{} `json:"items,omitempty"`
	Item             interface{} `json:"item,omitempty"`
}

type HTTPSubError struct {
	Domain       string `json:"domain,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Message      string `json:"message,omitempty"`
	Location     string `json:"location,omitempty"`
	LocationType string `json:"locationType,omitempty"`
	ExtendedHelp string `json:"extendedHelp,omitempty"`
	SendReport   string `json:"sendReport,omitempty"`
}

// HTTPError tells the status and error
type HTTPError struct {
	// Status string `json:"status"`
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Errors  []HTTPSubError `json:"errors"`
}

// HTTPRedirectError is an HTTPError with a redirect path
type HTTPRedirectError struct {
	HTTPError
	Redirect string `json:"redirect"`
}

package apperror

type AnError struct{ detailedError }
type MongoError struct{ detailedError }
type KubernetesError struct{ detailedError }
type HTTPResponseError struct{ detailedError }
type ConfigurationError struct{ detailedError }
type ConnectionError struct{ detailedError }
type MalformedRequestError struct{ detailedError }
type InvalidUsernameOrPasswordError struct{ detailedError }
type FieldError struct{ detailedError }
type ClusterAlreadyExists struct{ detailedError }
type InvalidAuthToken struct{ detailedError }
type SessionExpired struct{ detailedError }

// Example usage:
// return NewMongoError(err, http.StatusInternalServerError)
// return NewMongoError(fmt.Errorf("Some error occured: %w", err), http.StatusInternalServerError)
// return NewMongoError(fmt.Errorf("Some error occured: %w", err), http.StatusInternalServerError, Suberror{"loc", "msg"}, Suberror{"loc2", "msg2"})
func NewAnError(httpCode int, err error, suberrors ...Suberror) error {
	return AnError{
		detailedError{
			err:       err,
			English:   "An error has occured",
			Zhongwen:  "An error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewMongoError(httpCode int, err error, suberrors ...Suberror) error {
	return MongoError{
		detailedError{
			err:       err,
			English:   "Database error has occured (MongoDB)",
			Zhongwen:  "Database error has occured (MongoDB) but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewKubernetesError(httpCode int, err error, suberrors ...Suberror) error {
	return KubernetesError{
		detailedError{
			err:       err,
			English:   "Kubernetes error has occured",
			Zhongwen:  "Kubernetes error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewHTTPResponseError(httpCode int, err error, suberrors ...Suberror) error {
	return HTTPResponseError{
		detailedError{
			err:       err,
			English:   "An error has occured while writing response",
			Zhongwen:  "An error has occured while writing response but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewConfigurationError(httpCode int, err error, suberrors ...Suberror) error {
	return ConfigurationError{
		detailedError{
			err:       err,
			English:   "Backend configuration error occured",
			Zhongwen:  "Backend configuration error occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewConnectionError(httpCode int, err error, suberrors ...Suberror) error {
	return ConnectionError{
		detailedError{
			err:       err,
			English:   "A connection error occured",
			Zhongwen:  "A connection error occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewMalformedRequestError(httpCode int, err error, suberrors ...Suberror) error {
	return MalformedRequestError{
		detailedError{
			err:       err,
			English:   "Malformed request",
			Zhongwen:  "Malformed request but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewInvalidUsernameOrPasswordError(httpCode int, err error, suberrors ...Suberror) error {
	return InvalidUsernameOrPasswordError{
		detailedError{
			err:       err,
			English:   "Invalid username or password",
			Zhongwen:  "Invalid username or password but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewFieldError(httpCode int, err error, suberrors ...Suberror) error {
	return FieldError{
		detailedError{
			err:       err,
			English:   "Field missing or invalid",
			Zhongwen:  "Field missing or invalid but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewClusterAlreadyExists(httpCode int, err error, suberrors ...Suberror) error {
	return ClusterAlreadyExists{
		detailedError{
			err:       err,
			English:   "Cluster with this name already exists",
			Zhongwen:  "Cluster with this name already exists but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewInvalidAuthToken(httpCode int, err error, suberrors ...Suberror) error {
	return InvalidAuthToken{
		detailedError{
			err:       err,
			English:   "Invalid auth token",
			Zhongwen:  "Invalid auth token but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewSessionExpired(httpCode int, err error, suberrors ...Suberror) error {
	return SessionExpired{
		detailedError{
			err:       err,
			English:   "Session expired",
			Zhongwen:  "Session expired but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

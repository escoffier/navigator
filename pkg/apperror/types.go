package apperror

type AnError struct{ detailedError }
type MongoError struct{ detailedError }
type KubernetesError struct{ detailedError }
type CheckAlreadyInProgressError struct{ detailedError }
type HTTPResponseError struct{ detailedError }
type ConfigurationError struct{ detailedError }
type ConnectionError struct{ detailedError }
type MalformedRequestError struct{ detailedError }
type InvalidUsernameOrPasswordError struct{ detailedError }
type FieldError struct{ detailedError }
type ClusterAlreadyExists struct{ detailedError }
type InvalidAuthToken struct{ detailedError }
type SessionExpired struct{ detailedError }
type ClairError struct{ detailedError }
type DockerError struct{ detailedError }
type ClairMissingParentLayerError struct{ detailedError }
type HarborError struct{ detailedError }
type HarborUnauthorizedError struct{ detailedError }
type HarborForbiddenError struct{ detailedError }
type HarborScanAllInProgressError struct{ detailedError }
type RedisError struct{ detailedError }

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

func NewCheckAlreadyInProgressError(httpCode int, err error, suberrors ...Suberror) error {
	return CheckAlreadyInProgressError{
		detailedError{
			err:       err,
			English:   "Such compliance check is already in progress",
			Zhongwen:  "Such compliance check is already in progress but in 中文",
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

func NewClairError(httpCode int, err error, suberrors ...Suberror) error {
	return ClairError{
		detailedError{
			err:       err,
			English:   "Clair error has occured",
			Zhongwen:  "Clair error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewDockerError(httpCode int, err error, suberrors ...Suberror) error {
	return DockerError{
		detailedError{
			err:       err,
			English:   "Docker error has occured",
			Zhongwen:  "Docker error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewClairMissingParentLayerError(httpCode int, err error, suberrors ...Suberror) error {
	return ClairMissingParentLayerError{
		detailedError{
			err:       err,
			English:   "Clair scanning error: missing parent layer",
			Zhongwen:  "Clair scanning error: missing parent layer in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewHarborError(httpCode int, err error, suberrors ...Suberror) error {
	return HarborError{
		detailedError{
			err:       err,
			English:   "Harbor error has occured",
			Zhongwen:  "Harbor error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewHarborUnauthorizedError(httpCode int, err error, suberrors ...Suberror) error {
	return HarborUnauthorizedError{
		detailedError{
			err:       err,
			English:   "Harbor returned error 'Unauthorized', please check Harbor username/password",
			Zhongwen:  "Harbor returned error 'Unauthorized', please check Harbor username/password but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewHarborForbiddenError(httpCode int, err error, suberrors ...Suberror) error {
	return HarborForbiddenError{
		detailedError{
			err:       err,
			English:   "Harbor returned error 'Forbidden', please check if user has Administrator privileges",
			Zhongwen:  "Harbor returned error 'Forbidden', please check if user has Administrator privileges but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewHarborScanAllInProgressError(httpCode int, err error, suberrors ...Suberror) error {
	return HarborScanAllInProgressError{
		detailedError{
			err:       err,
			English:   "Harbor full scan is already in progress, please wait",
			Zhongwen:  "Harbor full scan is already in progress, please wait but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewRedisError(httpCode int, err error, suberrors ...Suberror) error {
	return RedisError{
		detailedError{
			err:       err,
			English:   "Redis error has occured",
			Zhongwen:  "Redis error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

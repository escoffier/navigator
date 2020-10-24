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
type MaxNumberOfClustersReached struct{ detailedError }
type InvalidAuthToken struct{ detailedError }
type SessionExpired struct{ detailedError }
type ClairError struct{ detailedError }
type DockerError struct{ detailedError }
type ClairUnprocessableLayerError struct{ detailedError }
type ClairMissingParentLayerError struct{ detailedError }
type HarborError struct{ detailedError }
type HarborUnauthorizedError struct{ detailedError }
type HarborForbiddenError struct{ detailedError }
type HarborScanAllInProgressError struct{ detailedError }
type RedisError struct{ detailedError }
type RulesError struct{ detailedError }
type ElasticError struct{ detailedError }
type RuleDoesntExistError struct{ detailedError }
type RuleAlreadyAppliedError struct{ detailedError }
type RuleNotAppliedError struct{ detailedError }

// Example usage:
// return NewMongoError(err, http.StatusInternalServerError)
// return NewMongoError(fmt.Errorf("Some error occurred: %w", err), http.StatusInternalServerError)
// return NewMongoError(fmt.Errorf("Some error occurred: %w", err), http.StatusInternalServerError, Suberror{"loc", "msg"}, Suberror{"loc2", "msg2"})
func NewAnError(httpCode int, err error, suberrors ...Suberror) error {
	return AnError{
		detailedError{
			err:       err,
			English:   "An error has occurred",
			Zhongwen:  "发生了错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewMongoError(httpCode int, err error, suberrors ...Suberror) error {
	return MongoError{
		detailedError{
			err:       err,
			English:   "Database error has occurred (MongoDB)",
			Zhongwen:  "发生数据库错误(MongoDB)",
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
			Zhongwen:  "发生Kubernetes错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewRulesError(httpCode int, err error, suberrors ...Suberror) error {
	return RulesError{
		detailedError{
			err:       err,
			English:   "Runtime detection rules error has occured",
			Zhongwen:  "Runtime detection rules error has occured, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewRuleNotAppliedError(httpCode int, err error, suberrors ...Suberror) error {
	return RuleNotAppliedError{
		detailedError{
			err:       err,
			English:   "Runtime detection rule is not applied",
			Zhongwen:  "Runtime detection rule is not applied, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewRuleAlreadyAppliedError(httpCode int, err error, suberrors ...Suberror) error {
	return RuleAlreadyAppliedError{
		detailedError{
			err:       err,
			English:   "Runtime detection rule already applied",
			Zhongwen:  "Runtime detection rule already applied, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewRuleDoesntExistError(httpCode int, err error, suberrors ...Suberror) error {
	return RuleDoesntExistError{
		detailedError{
			err:       err,
			English:   "Runtime detection rule doesn't exist",
			Zhongwen:  "Runtime detection rule doesn't exist, but in Chinese",
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
			Zhongwen:  "此类合规性检查已在进行中",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewHTTPResponseError(httpCode int, err error, suberrors ...Suberror) error {
	return HTTPResponseError{
		detailedError{
			err:       err,
			English:   "An error has occurred while writing response",
			Zhongwen:  "写入回应时发生错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewConfigurationError(httpCode int, err error, suberrors ...Suberror) error {
	return ConfigurationError{
		detailedError{
			err:       err,
			English:   "Backend configuration error occurred",
			Zhongwen:  "发生后端配置错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewConnectionError(httpCode int, err error, suberrors ...Suberror) error {
	return ConnectionError{
		detailedError{
			err:       err,
			English:   "A connection error occurred",
			Zhongwen:  "发生连接错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewElasticError(httpCode int, err error, suberrors ...Suberror) error {
	return ElasticError{
		detailedError{
			err:       err,
			English:   "Elasticsearch error",
			Zhongwen:  "Elasticsearch error, but in Chinese",
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
			Zhongwen:  "请求格式错误",
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
			Zhongwen:  "用户名或密码无效",
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
			Zhongwen:  "字段缺失或无效",
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
			Zhongwen:  "具有该名称的集群已存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewMaxNumberOfClustersReached(httpCode int, err error, suberrors ...Suberror) error {
	return MaxNumberOfClustersReached{
		detailedError{
			err:       err,
			English:   "Maximum number of clusters reached",
			Zhongwen:  "达到最大群集数",
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
			Zhongwen:  "无效的身份验证令牌",
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
			Zhongwen:  "会话已过期",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewClairError(httpCode int, err error, suberrors ...Suberror) error {
	return ClairError{
		detailedError{
			err:       err,
			English:   "Clair error has occurred",
			Zhongwen:  "发生了Clair错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewDockerError(httpCode int, err error, suberrors ...Suberror) error {
	return DockerError{
		detailedError{
			err:       err,
			English:   "Docker error has occurred",
			Zhongwen:  "发生Docker错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewClairUnprocessableLayerError(httpCode int, err error, suberrors ...Suberror) error {
	return ClairUnprocessableLayerError{
		detailedError{
			err:       err,
			English:   "Clair scanning error: layer unprocessable",
			Zhongwen:  "Clair扫描错误：不可处理的图层",
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
			Zhongwen:  "Clair扫描错误：缺少父层",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
		},
	}
}

func NewHarborError(httpCode int, err error, suberrors ...Suberror) error {
	return HarborError{
		detailedError{
			err:       err,
			English:   "Harbor error has occurred",
			Zhongwen:  "发生Harbor错误",
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
			Zhongwen:  "Harbor返回错误“未经授权”, 请检查用户名/密码",
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
			Zhongwen:  "Harbor返回错误“禁止”, 请检查用户是否具有管理员权限",
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
			Zhongwen:  "Harbor全面扫描已在进行中, 请稍候",
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

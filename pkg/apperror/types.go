package apperror

import "runtime"

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
type NoAccess struct{ detailedError }
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
type AlertAlreadyAcknowledged struct{ detailedError }
type ClusterError struct{ detailedError }
type ClusterDoesntExistError struct{ detailedError }
type AuditConfigError struct{ detailedError }
type CannotGetDiskUsageError struct{ detailedError }
type AuditConfigDoesntExistError struct{ detailedError }
type GarbageCollectionError struct{ detailedError }
type GarbageCollectionInProgressError struct{ detailedError }
type AssetDoesntExistError struct{ detailedError }
type RedisCacheError struct{ detailedError }

// Example usage:
// return NewMongoError(err, http.StatusInternalServerError)
// return NewMongoError(fmt.Errorf("Some error occurred: %w", err), http.StatusInternalServerError)
// return NewMongoError(fmt.Errorf("Some error occurred: %w", err), http.StatusInternalServerError, Suberror{"loc", "msg"}, Suberror{"loc2", "msg2"})
func NewAnError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "An error has occurred",
			Zhongwen:  "发生了错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewMongoError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MongoError{
		detailedError{
			err:       err,
			English:   "Database error has occurred (MongoDB)",
			Zhongwen:  "发生数据库错误(MongoDB)",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewKubernetesError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return KubernetesError{
		detailedError{
			err:       err,
			English:   "Kubernetes error has occured",
			Zhongwen:  "发生Kubernetes错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewRulesError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return RulesError{
		detailedError{
			err:       err,
			English:   "Runtime detection rules error has occured",
			Zhongwen:  "Runtime detection rules error has occured, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewRuleNotAppliedError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return RuleNotAppliedError{
		detailedError{
			err:       err,
			English:   "Runtime detection rule is not applied",
			Zhongwen:  "Runtime detection rule is not applied, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewRuleAlreadyAppliedError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return RuleAlreadyAppliedError{
		detailedError{
			err:       err,
			English:   "Runtime detection rule already applied",
			Zhongwen:  "Runtime detection rule already applied, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewRuleDoesntExistError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return RuleDoesntExistError{
		detailedError{
			err:       err,
			English:   "Runtime detection rule doesn't exist",
			Zhongwen:  "Runtime detection rule doesn't exist, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCheckAlreadyInProgressError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CheckAlreadyInProgressError{
		detailedError{
			err:       err,
			English:   "Such compliance check is already in progress",
			Zhongwen:  "此类合规性检查已在进行中",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewHTTPResponseError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return HTTPResponseError{
		detailedError{
			err:       err,
			English:   "An error has occurred while writing response",
			Zhongwen:  "写入回应时发生错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewConfigurationError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ConfigurationError{
		detailedError{
			err:       err,
			English:   "Backend configuration error occurred",
			Zhongwen:  "发生后端配置错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewConnectionError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ConnectionError{
		detailedError{
			err:       err,
			English:   "A connection error occurred",
			Zhongwen:  "发生连接错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewElasticError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ElasticError{
		detailedError{
			err:       err,
			English:   "Elasticsearch error",
			Zhongwen:  "Elasticsearch error, but in Chinese",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewMalformedRequestError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MalformedRequestError{
		detailedError{
			err:       err,
			English:   "Malformed request",
			Zhongwen:  "请求格式错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewInvalidUsernameOrPasswordError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return InvalidUsernameOrPasswordError{
		detailedError{
			err:       err,
			English:   "Invalid username or password",
			Zhongwen:  "用户名或密码无效",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewFieldError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return FieldError{
		detailedError{
			err:       err,
			English:   "Field missing or invalid",
			Zhongwen:  "字段缺失或无效",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewClusterAlreadyExists(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ClusterAlreadyExists{
		detailedError{
			err:       err,
			English:   "Cluster with this name already exists",
			Zhongwen:  "具有该名称的集群已存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewMaxNumberOfClustersReached(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MaxNumberOfClustersReached{
		detailedError{
			err:       err,
			English:   "Maximum number of clusters reached",
			Zhongwen:  "达到最大群集数",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewInvalidAuthToken(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return InvalidAuthToken{
		detailedError{
			err:       err,
			English:   "Invalid auth token",
			Zhongwen:  "无效的身份验证令牌",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewNoAccess(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return NoAccess{
		detailedError{
			err:       err,
			English:   "Access is Invalid",
			Zhongwen:  "没有此权限",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewSessionExpired(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return SessionExpired{
		detailedError{
			err:       err,
			English:   "Session expired",
			Zhongwen:  "会话已过期",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewClairError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ClairError{
		detailedError{
			err:       err,
			English:   "Clair error has occurred",
			Zhongwen:  "发生了Clair错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewDockerError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return DockerError{
		detailedError{
			err:       err,
			English:   "Docker error has occurred",
			Zhongwen:  "发生Docker错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewClairUnprocessableLayerError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ClairUnprocessableLayerError{
		detailedError{
			err:       err,
			English:   "Clair scanning error: layer unprocessable",
			Zhongwen:  "Clair扫描错误：不可处理的图层",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewClairMissingParentLayerError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ClairMissingParentLayerError{
		detailedError{
			err:       err,
			English:   "Clair scanning error: missing parent layer",
			Zhongwen:  "Clair扫描错误：缺少父层",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewHarborError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return HarborError{
		detailedError{
			err:       err,
			English:   "Harbor error has occurred",
			Zhongwen:  "发生Harbor错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewHarborUnauthorizedError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return HarborUnauthorizedError{
		detailedError{
			err:       err,
			English:   "Harbor returned error 'Unauthorized', please check Harbor username/password",
			Zhongwen:  "Harbor返回错误“未经授权”, 请检查用户名/密码",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewHarborForbiddenError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return HarborForbiddenError{
		detailedError{
			err:       err,
			English:   "Harbor returned error 'Forbidden', please check if user has Administrator privileges",
			Zhongwen:  "Harbor返回错误“禁止”, 请检查用户是否具有管理员权限",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewHarborScanAllInProgressError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return HarborScanAllInProgressError{
		detailedError{
			err:       err,
			English:   "Harbor full scan is already in progress, please wait",
			Zhongwen:  "Harbor全面扫描已在进行中, 请稍候",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewRedisError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return RedisError{
		detailedError{
			err:       err,
			English:   "Redis error has occured",
			Zhongwen:  "Redis error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewAlertAlreadyAcknowledgedError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AlertAlreadyAcknowledged{
		detailedError{
			err:       err,
			English:   "Alert already acknowledged",
			Zhongwen:  "Alert already acknowledged but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewClusterError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ClusterError{
		detailedError{
			err:       err,
			English:   "Cluster error has occured",
			Zhongwen:  "Cluster error has occured but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewClusterDoesntExistError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ClusterDoesntExistError{
		detailedError{
			err:       err,
			English:   "Cluster does not exist",
			Zhongwen:  "Cluster does not exist but in 中文",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewAuditConfigError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AuditConfigError{
		detailedError{
			err:       err,
			English:   "Audit config error occured",
			Zhongwen:  "审计配置发生错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotGetDiskUsageError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotGetDiskUsageError{
		detailedError{
			err:       err,
			English:   "Cannot get disk usage info",
			Zhongwen:  "无法获取磁盘用量信息",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewAuditConfigDoesntExistError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AuditConfigDoesntExistError{
		detailedError{
			err:       err,
			English:   "Audit config does not exist",
			Zhongwen:  "审计配置不存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewGarbageCollectionError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return GarbageCollectionError{
		detailedError{
			err:       err,
			English:   "Garbage collection error",
			Zhongwen:  "垃圾回收錯誤",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewGarbageCollectionInProgressError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return GarbageCollectionInProgressError{
		detailedError{
			err:       err,
			English:   "Garbage collection in progress",
			Zhongwen:  "垃圾回收正在進行中",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewAssetDoesntExistError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AssetDoesntExistError{
		detailedError{
			err:       err,
			English:   "Asset does not exist",
			Zhongwen:  "資產不存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewRedisCacheError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return RedisCacheError{
		detailedError{
			err:       err,
			English:   "Redis cache error",
			Zhongwen:  "Redis緩存錯誤",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

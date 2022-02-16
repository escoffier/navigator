package apperror

import (
	"runtime"
)

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
type NotFoundError struct{ detailedError }
type GCTaskError struct{ detailedError }
type ArgError struct{ detailedError }
type PolicyError struct{ detailedError }
type PolicyTrainingError struct{ detailedError }
type CannotAddResourceToActivePolicyError struct{ detailedError }
type CannotAddResourceToPolicyInTrainingError struct{ detailedError }
type PolicyNotFoundError struct{ detailedError }
type ResourceNotFoundError struct{ detailedError }
type ResourceAlreadyAttachedToPolicyError struct{ detailedError }
type ResourceAttachedToDifferentPolicyError struct{ detailedError }
type CannotRemoveResourceFromActivePolicyError struct{ detailedError }
type CannotRemoveResourceFromPolicyInTrainingError struct{ detailedError }
type ResourceNotAttachedToPolicyError struct{ detailedError }
type UnknownSecurityModeError struct{ detailedError }
type ProfileUpdateError struct{ detailedError }
type CannotDeactivatePolicyProfilesAreInTrainingError struct{ detailedError }
type CannotDeleteActivePolicyError struct{ detailedError }
type CannotUpdateConfigOfCurrentlyTrainedProfileError struct{ detailedError }
type CannotChangeProfileStatusWhenPolicyIsActiveError struct{ detailedError }
type UnknownSecurityProfileKindError struct{ detailedError }
type CannotStartTrainingThatIsEmptyResourcesError struct{ detailedError }
type CannotStartTrainingThatIsInProgressError struct{ detailedError }
type CannotStartAPausedTrainingError struct{ detailedError }
type CannotAbortNonStartedTrainingError struct{ detailedError }
type CannotSuspendAPausedTrainingError struct{ detailedError }
type CannotSuspendANonStartedTrainingError struct{ detailedError }
type CannotResumeAnInProgressTrainingError struct{ detailedError }
type CannotResumeANonStartedTrainingError struct{ detailedError }
type CannotStopANonStartedTrainingError struct{ detailedError }
type MissingStartTrainingTimeInTrainedProfileError struct{ detailedError }
type PolicyAlreadySetToRequestedStatus struct{ detailedError }
type PolicyAlreadySetToRequestedMode struct{ detailedError }
type ProfileAlreadySetToRequestedStatus struct{ detailedError }
type CannotChangePolicyStatusAreInTrainingError struct{ detailedError }
type CommonError struct{ detailedError }
type MissingCommandSentError struct{ detailedError }
type MissingFileSentError struct{ detailedError }
type MissingSyscallSentError struct{ detailedError }
type MissingWorkingDirSentError struct{ detailedError }
type FileSentNotAbsoluteError struct{ detailedError }
type WorkingDirSentNotAbsoluteError struct{ detailedError }
type InvalidAccessSentError struct{ detailedError }
type InvalidSyscallSentError struct{ detailedError }
type CannotUpdateProfileThatIsTrained struct{ detailedError }
type DuplicateEntrySentError struct{ detailedError }
type BaitNameDuplicateError struct{ detailedError }
type ResourceNameDuplicateError struct{ detailedError }
type AddBaitServiceError struct{ detailedError }

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
			Chinese:   "发生了错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCaptchaError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "captcha value is wrong",
			Chinese:   "验证码错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}
func NewLoginError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "username and password not match",
			Chinese:   "用户名/密码错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewAccountBanError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "the account is banned",
			Chinese:   "账户已被锁定，请联系管理员",
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
			English:   "An exception occurred on the server",
			Chinese:   "服务器开小差了",
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
			Chinese:   "发生Kubernetes错误",
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
			Chinese:   "Runtime detection rules error has occured, but in Chinese",
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
			Chinese:   "Runtime detection rule is not applied, but in Chinese",
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
			Chinese:   "Runtime detection rule already applied, but in Chinese",
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
			Chinese:   "Runtime detection rule doesn't exist, but in Chinese",
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
			English:   "The specific compliance check is already in progress",
			Chinese:   "此类合规性检查已在进行中",
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
			Chinese:   "写入回应时发生错误",
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
			Chinese:   "发生后端配置错误",
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
			Chinese:   "发生连接错误",
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
			Chinese:   "Elasticsearch error, but in Chinese",
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
			Chinese:   "请求格式错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewPasswordNotMatchError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MalformedRequestError{
		detailedError{
			err:       err,
			English:   "Password not match",
			Chinese:   "密码不匹配",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewGCTaskInProgressError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return GCTaskError{
		detailedError{
			err:       err,
			English:   "GC task is in progress",
			Chinese:   "清理任务正在进行中",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewInvalidArgError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ArgError{
		detailedError{
			err:       err,
			English:   "invalid args",
			Chinese:   "参数非法",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func BusyRequestError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MalformedRequestError{
		detailedError{
			err:       err,
			English:   "busy request",
			Chinese:   "频繁请求，已经被服务器拦截",
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
			Chinese:   "用户名或密码无效",
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
			Chinese:   "字段缺失或无效",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func ScanImageGoingErr(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return FieldError{
		detailedError{
			err:       err,
			English:   "Scan online image going",
			Chinese:   "正在扫描在线镜像",
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
			Chinese:   "具有该名称的集群已存在",
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
			Chinese:   "达到最大群集数",
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
			Chinese:   "无效的身份验证令牌",
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
			Chinese:   "没有此权限",
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
			Chinese:   "会话已过期",
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
			Chinese:   "发生了Clair错误",
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
			Chinese:   "发生Docker错误",
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
			Chinese:   "Clair扫描错误：不可处理的图层",
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
			Chinese:   "Clair扫描错误：缺少父层",
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
			Chinese:   "发生Harbor错误",
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
			Chinese:   "Harbor返回错误“未经授权”, 请检查用户名/密码",
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
			Chinese:   "Harbor返回错误“禁止”, 请检查用户是否具有管理员权限",
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
			Chinese:   "Harbor全面扫描已在进行中, 请稍候",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func HarborGetProgressError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return HarborScanAllInProgressError{
		detailedError{
			err:       err,
			English:   "Harbor get  progress error",
			Chinese:   "Harbor 获取project 错误",
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
			Chinese:   "Redis error has occured but in 中文",
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
			Chinese:   "Alert already acknowledged but in 中文",
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
			Chinese:   "Cluster error has occured but in 中文",
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
			Chinese:   "Cluster does not exist but in 中文",
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
			Chinese:   "审计配置发生错误",
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
			Chinese:   "无法获取磁盘用量信息",
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
			Chinese:   "审计配置不存在",
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
			Chinese:   "垃圾回收錯誤",
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
			Chinese:   "垃圾回收正在進行中",
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
			Chinese:   "資產不存在",
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
			Chinese:   "Redis緩存錯誤",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func LoginError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "Username or password error",
			Chinese:   "用户名或密码错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func PostgresError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MongoError{
		detailedError{
			err:       err,
			English:   "An exception occurred on the server",
			Chinese:   "服务器开小差了",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func UserExistError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "User exist",
			Chinese:   "用户已经存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}
func UserNotExistError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "User not exist",
			Chinese:   "用户不存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func SendmailError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "Send mail error",
			Chinese:   "发送邮件错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func EmailForMatError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "Email format error",
			Chinese:   "邮件格式错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func AccountUnActive(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AnError{
		detailedError{
			err:       err,
			English:   "Account is not activated",
			Chinese:   "账户未激活",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewProfileDoestExistError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MongoError{
		detailedError{
			err:       err,
			English:   "Security profile doesn't exist",
			Chinese:   "安全配置文件不存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewNotFoundError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return NotFoundError{
		detailedError{
			err:       err,
			English:   "Not found",
			Chinese:   "未找到",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewPolicyError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return PolicyError{
		detailedError{
			err:       err,
			English:   "Security Policy failure",
			Chinese:   "安全策略失敗",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewPolicyTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return PolicyTrainingError{
		detailedError{
			err:       err,
			English:   "Security Policy Training failure",
			Chinese:   "安全策略訓練失敗",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotAddResourceToActivePolicyError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotAddResourceToActivePolicyError{
		detailedError{
			err:       err,
			English:   "Cannot add resource to active policy",
			Chinese:   "无法将资源添加到已启用的策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotAddResourceToPolicyInTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotAddResourceToPolicyInTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot add resource to policy in training",
			Chinese:   "无法将资源添加到正在训练中的策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewPolicyNotFoundError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return PolicyNotFoundError{
		detailedError{
			err:       err,
			English:   "Policy not found",
			Chinese:   "未找到策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewResourceNotFoundError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ResourceNotFoundError{
		detailedError{
			err:       err,
			English:   "Resource not found",
			Chinese:   "找不到资源",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewResourceAlreadyAttachedToPolicyError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ResourceAlreadyAttachedToPolicyError{
		detailedError{
			err:       err,
			English:   "Resource already attached to policy",
			Chinese:   "资源已经添加到策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewResourceAttachedToDifferentPolicyError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ResourceAttachedToDifferentPolicyError{
		detailedError{
			err:       err,
			English:   "Resource attached to different policy",
			Chinese:   "资源已经添加到其他策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotRemoveResourceFromActivePolicyError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotRemoveResourceFromActivePolicyError{
		detailedError{
			err:       err,
			English:   "Cannot remove resource from active policy",
			Chinese:   "无法删除启用中策略的资源",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotRemoveResourceFromPolicyInTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotRemoveResourceFromPolicyInTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot remove resource from policy in training",
			Chinese:   "无法从训练中的策略里删除资源",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewResourceNotAttachedToPolicyError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ResourceNotAttachedToPolicyError{
		detailedError{
			err:       err,
			English:   "Resource not attached to policy",
			Chinese:   "资源未添加到策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewUnknownSecurityModeError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return UnknownSecurityModeError{
		detailedError{
			err:       err,
			English:   "Unknown security mode",
			Chinese:   "未知的安全模式",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewProfileUpdateError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ProfileUpdateError{
		detailedError{
			err:       err,
			English:   "Profile update error",
			Chinese:   "配置文件更新错误",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotDeactivatePolicyProfilesAreInTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotDeactivatePolicyProfilesAreInTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot deactivate policy, because some profiles are in training",
			Chinese:   "无法停用策略，因为某些配置文件正在训练中",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotDeleteActivePolicyError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotDeleteActivePolicyError{
		detailedError{
			err:       err,
			English:   "Cannot delete active policy",
			Chinese:   "无法刪除已启用的策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotUpdateConfigOfCurrentlyTrainedProfileError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotUpdateConfigOfCurrentlyTrainedProfileError{
		detailedError{
			err:       err,
			English:   "Cannot update configuration of currently trained profile",
			Chinese:   "无法更新当前训练的配置文件",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotChangeProfileStatusWhenPolicyIsActiveError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotChangeProfileStatusWhenPolicyIsActiveError{
		detailedError{
			err:       err,
			English:   "Cannot change profile status when policy is active",
			Chinese:   "策略开启时无法修改默认动作",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewUnknownSecurityProfileKindError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return UnknownSecurityProfileKindError{
		detailedError{
			err:       err,
			English:   "Unknown security profile kind",
			Chinese:   "未知的安全配置文件类型",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotStartTrainingThatIsEmptyResourcesError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotStartTrainingThatIsEmptyResourcesError{
		detailedError{
			err:       err,
			English:   "Cannot start training that policy's empty  resources",
			Chinese:   "无法开始训练资源为空的策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotStartTrainingThatIsInProgressError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotStartTrainingThatIsInProgressError{
		detailedError{
			err:       err,
			English:   "Cannot start training that is in progress",
			Chinese:   "无法开始正在进行的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotStartAPausedTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotStartAPausedTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot start training that is paused",
			Chinese:   "无法开始暂停的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotAbortNonStartedTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotAbortNonStartedTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot abort a non started training",
			Chinese:   "无法终止未开始的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotSuspendAPausedTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotSuspendAPausedTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot suspend a paused training",
			Chinese:   "无法暂停已经暂停的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotSuspendANonStartedTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotSuspendANonStartedTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot suspend a non started training",
			Chinese:   "无法暂停未开始的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotResumeAnInProgressTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotResumeAnInProgressTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot resume an in progress training",
			Chinese:   "无法继续正在进行的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotResumeANonStartedTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotResumeANonStartedTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot resume an non started training",
			Chinese:   "无法继续未开始的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotStopANonStartedTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotStopANonStartedTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot stop a non started training",
			Chinese:   "无法停止未开始的训练",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCommonError(httpCode int, err error, zhMsg, enMsg string) error {
	_, file, line, _ := runtime.Caller(1)
	return CommonError{
		detailedError{
			err:      err,
			English:  enMsg,
			Chinese:  zhMsg,
			HTTPCode: httpCode,
			File:     file,
			Line:     line,
		},
	}
}

func NewMissingStartTrainingTimeInTrainedProfileError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MissingStartTrainingTimeInTrainedProfileError{
		detailedError{
			err:       err,
			English:   "Missing 'startTrainingTime' in trained profile",
			Chinese:   "训练配置中缺少'开始时间'",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewPolicyAlreadySetToRequestedStatus(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return PolicyAlreadySetToRequestedStatus{
		detailedError{
			err:       err,
			English:   "Policy already set to requested status",
			Chinese:   "策略已经设置为请求状态",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewPolicyAlreadySetToRequestedMode(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return PolicyAlreadySetToRequestedMode{
		detailedError{
			err:       err,
			English:   "Policy already set to requested mode",
			Chinese:   "策略已经设置为请求模式",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewProfileAlreadySetToRequestedStatus(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ProfileAlreadySetToRequestedStatus{
		detailedError{
			err:       err,
			English:   "Profile already set to requested status",
			Chinese:   "配置已经设置为请求状态",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotChangePolicyStatusAreInTrainingError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotChangePolicyStatusAreInTrainingError{
		detailedError{
			err:       err,
			English:   "Cannot change policy status, there are profiles in training",
			Chinese:   "无法修改配置，配置文件正在训练中",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewCannotUpdateProfileThatIsTrained(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return CannotUpdateProfileThatIsTrained{
		detailedError{
			err:       err,
			English:   "Cannot update policy that is in training",
			Chinese:   "无法更新正在训练中的策略",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewInvalidAccessSentError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return InvalidAccessSentError{
		detailedError{
			err:       err,
			English:   "Invalid file access sent",
			Chinese:   "输入的的文件访问无效",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewInvalidSyscallSentError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return InvalidSyscallSentError{
		detailedError{
			err:       err,
			English:   "Invalid syscall sent",
			Chinese:   "输入的系统调用无效",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewFileSentNotAbsoluteError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return FileSentNotAbsoluteError{
		detailedError{
			err:       err,
			English:   "Sent file is not absolute path",
			Chinese:   "输入的文件不是绝对路径",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewMissingFileSentError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MissingFileSentError{
		detailedError{
			err:       err,
			English:   "Empty filepath sent",
			Chinese:   "输入空的文件路径",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewMissingWorkingDirSentError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MissingWorkingDirSentError{
		detailedError{
			err:       err,
			English:   "Empty working directory sent",
			Chinese:   "输入空的文件目录",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewMissingSyscallSentError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MissingSyscallSentError{
		detailedError{
			err:       err,
			English:   "Empty syscall sent",
			Chinese:   "输入空的系统调用",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewWorkingDirSentNotAbsoluteError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return WorkingDirSentNotAbsoluteError{
		detailedError{
			err:       err,
			English:   "Sent working directory is not absolute path",
			Chinese:   "输入的工作路径不是绝对路径",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewMissingCommandSentError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return MissingCommandSentError{
		detailedError{
			err:       err,
			English:   "Empty command sent",
			Chinese:   "输入空命令",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewDuplicateEntrySentError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return DuplicateEntrySentError{
		detailedError{
			err:       err,
			English:   "Duplicate entry sent",
			Chinese:   "输入的条目已经存在",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewBaitNameDuplicateError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return BaitNameDuplicateError{
		detailedError{
			err:       err,
			English:   "服务名称重复",
			Chinese:   "服务名称重复",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewResourceNameDuplicateError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return ResourceNameDuplicateError{
		detailedError{
			err:       err,
			English:   "资源名称重复",
			Chinese:   "资源名称重复",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

func NewAddBaitServiceError(httpCode int, err error, suberrors ...Suberror) error {
	_, file, line, _ := runtime.Caller(1)

	return AddBaitServiceError{
		detailedError{
			err:       err,
			English:   "新增失败，请重试",
			Chinese:   "新增失败，请重试",
			HTTPCode:  httpCode,
			Suberrors: suberrors,
			File:      file,
			Line:      line,
		},
	}
}

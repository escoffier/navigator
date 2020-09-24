package locale

import "net/http"

type LocaleErrCode int

const (
	AnError LocaleErrCode = iota
	MongoError
	ElasticsearchError
	EtcdError
	KubernetesError
	HTTPResponseError
	ConfigurationError
	ConnectionError
	MalformedRequestError
	InvalidUsernameOrPasswordError
	FieldError
	ClusterAlreadyExists
	InvalidAuthToken
	SessionExpired
)

var translationTable = map[LocaleErrCode]map[string]string{
	AnError: map[string]string{
		"en": "An error has occured",
		"zh": "An error has occured but in 中文",
	},
	MongoError: map[string]string{
		"en": "Database error has occured (MongoDB)",
		"zh": "Database error has occured (MongoDB) but in 中文",
	},
	ElasticsearchError: map[string]string{
		"en": "Database error has occured (Elasticsearch)",
		"zh": "Database error has occured (Elasticsearch) but in 中文",
	},
	EtcdError: map[string]string{
		"en": "Database error has occured (Etcd)",
		"zh": "Database error has occured (Etcd) but in 中文",
	},
	KubernetesError: map[string]string{
		"en": "Kubernetes error has occured",
		"zh": "Kubernetes error has occured but in 中文",
	},
	HTTPResponseError: map[string]string{
		"en": "An error has occured while writing response",
		"zh": "An error has occured while writing response but in 中文",
	},
	ConfigurationError: map[string]string{
		"en": "Backend configuration error occured",
		"zh": "Backend configuration error occured but in 中文",
	},
	ConnectionError: map[string]string{
		"en": "A connection error occured",
		"zh": "A connection error occured but in 中文",
	},
	MalformedRequestError: map[string]string{
		"en": "Malformed request",
		"zh": "Malformed request but in 中文",
	},
	InvalidUsernameOrPasswordError: map[string]string{
		"en": "Invalid username or password",
		"zh": "Invalid username or password but in 中文",
	},
	FieldError: map[string]string{
		"en": "Field missing or invalid",
		"zh": "Field missing or invalid but in 中文",
	},
	ClusterAlreadyExists: map[string]string{
		"en": "Cluster with this name already exists",
		"zh": "Cluster with this name already exists but in 中文",
	},
	InvalidAuthToken: map[string]string{
		"en": "Invalid auth token",
		"zh": "Invalid auth token but in 中文",
	},
	SessionExpired: map[string]string{
		"en": "Session expired",
		"zh": "Session expired but in 中文",
	},
}

func Error(errType LocaleErrCode, r *http.Request) string {
	lang := "en"
	if r != nil {
		lang = r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "en"
		}
	}

	translations, ok := translationTable[errType]
	if !ok {
		return "Failed to localize error (errType invalid)"
	}
	translation, ok := translations[lang]
	if !ok {
		// Backup to English
		return translations["en"]
	}
	return translation
}

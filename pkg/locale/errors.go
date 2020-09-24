package locale

import "net/http"

const (
	AnError = iota
	MongoError
	ElasticsearchError
	EtcdError
	HTTPResponseError
	ConnectionError
	MalformedRequestError
	InvalidUsernameOrPasswordError
	FieldError
	ClusterAlreadyExists
	InvalidAuthToken
	SessionExpired
)

var translationTable = map[int]map[string]string{
	AnError: map[string]string{
		"en": "An error has occured",
		"zh": "An error has occured but in Chinese",
	},
	MongoError: map[string]string{
		"en": "Database error has occured (MongoDB)",
		"zh": "Database error has occured (MongoDB) but in Chinese",
	},
	ElasticsearchError: map[string]string{
		"en": "Database error has occured (Elasticsearch)",
		"zh": "Database error has occured (Elasticsearch) but in Chinese",
	},
	EtcdError: map[string]string{
		"en": "Database error has occured (Etcd)",
		"zh": "Database error has occured (Etcd) but in Chinese",
	},
	HTTPResponseError: map[string]string{
		"en": "An error has occured while writing response",
		"zh": "An error has occured while writing response but in Chinese",
	},
	ConnectionError: map[string]string{
		"en": "A connection error occured",
		"zh": "A connection error occured but in Chinese",
	},
	MalformedRequestError: map[string]string{
		"en": "Malformed request",
		"zh": "Malformed request but in Chinese",
	},
	InvalidUsernameOrPasswordError: map[string]string{
		"en": "Invalid username or password",
		"zh": "Invalid username or password but in Chinese",
	},
	FieldError: map[string]string{
		"en": "Field missing or invalid",
		"zh": "Field missing or invalid but in Chinese",
	},
	ClusterAlreadyExists: map[string]string{
		"en": "Cluster with this name already exists",
		"zh": "Cluster with this name already exists but in Chinese",
	},
	InvalidAuthToken: map[string]string{
		"en": "Invalid auth token",
		"zh": "Invalid auth token but in Chinese",
	},
	SessionExpired: map[string]string{
		"en": "Session expired",
		"zh": "Session expired but in Chinese",
	},
}

func Error(errType int, r *http.Request) string {
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

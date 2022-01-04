package env

import "gitlab.com/piccolo_su/vegeta/pkg/util"

const (
	ElasticURL        = "ELASTIC_URL"
	DefaultElasticURL = "http://elasticsearch-svc:9200"

	ElasticUsername        = "ELASTIC_USERNAME"
	DefaultElasticUsername = "username"

	ElasticPassword = "ELASTIC_PASSWORD"
)

func GetElasticURL() string {
	return util.GetEnvWithDefault(ElasticURL, DefaultElasticURL)
}

func GetElasticUsername() string {
	return util.GetEnvWithDefault(ElasticUsername, DefaultElasticUsername)
}

func GetElasticPassword() string {
	return util.GetEnvWithDefault(ElasticPassword, "")
}

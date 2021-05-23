package env

import "os"

const (
	TaskID = "TASK_ID"

	TTLDayOffset = "TTL_DAY_OFFSET"

	ConfPath        = "CONF_PATH"
	DefaultConfPath = "/conf/conf.json"

	MongoUsername        = "MONGO_USERNAME"
	DefaultMongoUsername = "redstone"

	MongoPassword = "MONGO_PASSWORD"

	MongoEndpoint        = "MONGO_ENDPOINT"
	DefaultMongoEndpoint = "tensorsec-mongodb:27017"

	MongoDatabase        = "MONGO_DATABASE"
	DefaultMongoDatabase = "vegeta"

	MongoReadPreference        = "MONGO_READ_PREFERENCE"
	DefaultMongoReadPreference = "secondary"

	PostgresHost        = "PGSQL_HOST"
	DefaultPostgresHost = "tensorsec-postgresql"

	PostgresUser        = "PGSQL_USER"
	DefaultPostgresUser = "postgres"

	PostgresDBName        = "PGSQL_DBNAME"
	DefaultPostgresDBName = "postgres"

	PostgresSSLMode        = "PGSQL_SSL_MODE"
	DefaultPostgresSSLMode = "disable"

	ElasticURL        = "ELASTIC_URL"
	DefaultElasticURL = "http://tensorsec-elasticsearch-master:9200"

	PostgresPassword = "PGSQL_PASSWORD"

	AuditPath        = "AUDIT_PATH"
	DefaultAuditPath = "/audit"
)

func GetEnvWithDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

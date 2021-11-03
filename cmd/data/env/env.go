package env

const (
	TaskID          = "TASK_ID"
	TTLDayOffset    = "TTL_DAY_OFFSET"
	ConfPath        = "CONF_PATH"
	DefaultConfPath = "/conf/conf.json"

	PostgresHost           = "PGSQL_HOST"
	DefaultPostgresHost    = "tensorsec-postgresql"
	PostgresUser           = "PGSQL_USER"
	DefaultPostgresUser    = "postgres"
	PostgresDBName         = "PGSQL_DBNAME"
	DefaultPostgresDBName  = "postgres"
	PostgresSSLMode        = "PGSQL_SSL_MODE"
	DefaultPostgresSSLMode = "disable"
	PostgresPassword       = "PGSQL_PASSWORD"

	ElasticURL        = "ELASTIC_URL"
	DefaultElasticURL = "http://tensorsec-elasticsearch-master:9200"

	AuditPath        = "AUDIT_PATH"
	DefaultAuditPath = "/audit"
)

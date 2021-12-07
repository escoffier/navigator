package env

const (
	TaskID          = "TASK_ID"
	TTLDayOffset    = "TTL_DAY_OFFSET"
	ConfPath        = "CONF_PATH"
	DefaultConfPath = "/conf/conf.json"

	RDBHost           = "RDB_HOST"
	DefaultRDBHost    = "tensorsec-postgresql"
	RDBUser           = "RDB_USER"
	DefaultRDBUser    = "postgres"
	RDBDBName         = "RDB_DBNAME"
	DefaultRDBDBName  = "postgres"
	RDBSSLMode        = "RDB_SSLMODE"
	DefaultRDBSSLMode = "disable"
	RDBPassword       = "RDB_PASSWORD"
	RDBPort           = "RDB_PORT"

	ElasticURL      = "ELASTIC_URL"
	ElasticUsername = "ELASTIC_USERNAME"
	ElasticPassword = "ELASTIC_PASSWORD"

	AuditPath        = "AUDIT_PATH"
	DefaultAuditPath = "/audit"
)

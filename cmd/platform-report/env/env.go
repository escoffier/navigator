package env

const (
	UUID                  = "UUID"
	StartTimestamp        = "START_TIMESTAMP"
	EndTimestamp          = "END_TIMESTAMP"
	MaxTaskTimeSec        = "MAX_TASK_TIME_SEC"
	DefaultMaxTaskTimeSec = 7200
	TemplateID            = "TEMPLATE_ID"
	Image                 = "PLATFORM_REPORTER_IMAGE"

	NotifyBaseURL        = "Notify_BASE_URL"
	EmailHost            = "EMAIL_HOST"
	DefaultEmailHost     = "smtp.feishu.cn"
	EmailPort            = "EMAIL_PORT"
	DefaultEmailPort     = 465
	EmailUsername        = "EMAIL_USERNAME"
	DefaultEmailUsername = "console-robot@tensorsecurity.cn"
	EmailPassword        = "EMAIL_PASSWORD"
	DefaultEmailPassword = "r8UJgg7ejpSoDOAF"

	PostgresHost           = "PGSQL_HOST"
	DefaultPostgresHost    = "tensorsec-postgresql"
	PostgresUser           = "PGSQL_USER"
	DefaultPostgresUser    = "postgres"
	PostgresDBName         = "PGSQL_DBNAME"
	DefaultPostgresDBName  = "postgres"
	PostgresSSLMode        = "PGSQL_SSL_MODE"
	DefaultPostgresSSLMode = "disable"
	PostgresPassword       = "PGSQL_PASSWORD"
	PostgresPort           = "PGSQL_PORT"
	DefaultPostgresPort    = 5432
)

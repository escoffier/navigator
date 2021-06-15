package migrate

type Database struct {
	Dialect  string
	Host     string
	Port     uint
	User     string
	Password string
	Name     string
	Charset  string
	MigrateTable string
}


type Config struct {
	LogLevel  string // debug, info, warn, error, fatal or panic
	LogFormat string // json or text
	Env       string
	Database  Database
}

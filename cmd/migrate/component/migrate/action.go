package migrate

import (
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"net/url"
)

// Logger implement migrate log
type Logger struct{}

func (_ *Logger) Printf(format string, v ...interface{}) {
	logging.GetLogger().Info().Msgf(format,v)
}

func (_ *Logger) Verbose() bool {
	return true
}

type FileMigration struct {
	Dialect         string
	Host            string
	Port            uint
	User            string
	Password        string
	Name            string
	Charset         string
	Versions        string
	MigrateTable    string
	SourceUrl       string
}

func NewFileMigration(c Database) *FileMigration {
	return &FileMigration{
		Dialect:          c.Dialect,
		Host:             c.Host,
		Port:             c.Port,
		User:             c.User,
		Password:         c.Password,
		Charset:          c.Charset,
		Name:             c.Name,
		MigrateTable:     c.MigrateTable,
	}
}

func (m *FileMigration) create() *migrate.Migrate {
	var sourceUrl = fmt.Sprintf("file://%s", m.Versions)
	var dbUrl string
	switch m.Dialect {
	case "postgres":
		var userInfo = url.UserPassword(m.User, m.Password).String()
		dbUrl = fmt.Sprintf("%s://%s@%s:%d/%s?sslmode=disable&x-migrations-table=%s",
			m.Dialect, userInfo, m.Host, m.Port,m.Name, m.MigrateTable)
	default:
		logging.GetLogger().Fatal().Msgf("unrecognized database dialect,%v",m.Dialect)
	}

	logging.GetLogger().Info().Msgf("migrate from versions in directory %s",sourceUrl)
	logging.GetLogger().Info().Msgf("migrate target database %s",dbUrl)
	migrateInstance, err := migrate.New(sourceUrl, dbUrl)
	if err != nil {
		logging.GetLogger().Fatal().Msgf("create migrate connection failed,%v",err)
	}
	migrateInstance.Log = &Logger{}
	m.SourceUrl = sourceUrl
	return migrateInstance
}

func (m *FileMigration) Upgrade() {
	logging.GetLogger().Info().Msg("do upgrade...")
	var migrateInstance = m.create()
	var err = migrateInstance.Up()
	if err != nil {
		if err == migrate.ErrNoChange {
			logging.GetLogger().Warn().Msgf("migrate.ErrNoChange %v",err)
		} else if _, ok := err.(migrate.ErrDirty); ok {
			logging.GetLogger().Error().Msg("Last migration failed, you must solve the database state problem and try again！")
		} else {
			logging.GetLogger().Error().Msgf("Failed %v",err)
		}
	} else {
		logging.GetLogger().Info().Msg("OK")
	}
}

func (m *FileMigration) Downgrade() {
	logging.GetLogger().Info().Msg("do downgrade...")
	var migrateInstance = m.create()
	var err = migrateInstance.Steps(-1)
	if err != nil {
		logging.GetLogger().Error().Msgf("Failed %v",err)
	} else if _, ok := err.(migrate.ErrDirty); ok {
		logging.GetLogger().Error().Msg("Last migration failed, you must solve the database state problem and try again！")
	} else {
		logging.GetLogger().Info().Msg("OK")
	}
}

func (m *FileMigration) ForceResetDown() {
	var migrateInstance = m.create()
	var ver, dirty, err = migrateInstance.Version()
	if err != nil {
		logging.GetLogger().Fatal().Msgf("Get current version failed %v",err)
	}
	if !dirty {
		logging.GetLogger().Fatal().Msg("Forbidden reset if database schema is not dirty.")
	}

	logging.GetLogger().Info().Msgf("Remove current version dirty state,version",ver)
	err = migrateInstance.Force(int(ver))
	if err != nil {
		logging.GetLogger().Fatal().Msgf("Force version Failed %v",err)
	}

	logging.GetLogger().Info().Msgf("Downgrade current version to version %v",ver)
	err = migrateInstance.Steps(-1)
	if err != nil {
		logging.GetLogger().Fatal().Msgf("Force downgrade failed. You must solve the problem manually,%v",err)
	} else {
		ver, _, _ = migrateInstance.Version()
		logging.GetLogger().Info().Msgf("Force downgrade successfully,version %v",ver)
	}

}


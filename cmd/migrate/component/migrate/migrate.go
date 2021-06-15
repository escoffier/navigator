package migrate

import (
	"fmt"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var (
	VersionsDir     string
	ConfigFile      string
	conf            Config
)

const (
	ActionUp            = "up"
	ActionDown          = "down"
	ActionNew           = "new"
	MaxTitleLen         = 40
	DefaultMigrateTable = "tensor_migration"

	AppName             = "tensor-migrate"
	DefaultConfigFile   = "config.yaml"
	EnvPrefix           = "TENSORSEC_MIGRATE"
)

func SetViperConfig(cfgFile string, name string, envPrefix string) error {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			return err
		}

		viper.SetConfigName(DefaultConfigFile)
		viper.AddConfigPath(".")
		viper.AddConfigPath(fmt.Sprintf("%s/.%s/", home, name))
		viper.AddConfigPath(fmt.Sprintf("/etc/%s/", name))

		viper.AutomaticEnv()
		viper.SetEnvPrefix(envPrefix)
	}

	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	return nil
}

func InitConfig(cfgFile string) error {
	var err = SetViperConfig(cfgFile, AppName, EnvPrefix)
	if err != nil {
		return errors.Wrap(err, "config viper failed")
	}

	if err := viper.Unmarshal(&conf); err != nil {
		return errors.Wrap(err, "unmarshal config failed")
	}

	if conf.Database.MigrateTable == "" {
		conf.Database.MigrateTable = DefaultMigrateTable
	}

	return nil
}

func RunMigrate(action string, cmd *cobra.Command) {

	var m = NewFileMigration(conf.Database)
	var absPath, err = filepath.Abs(VersionsDir)
	if err != nil {
		logging.GetLogger().Error().Msgf("get version files directory failed,versionDir %s,err %v",absPath,err)
		return
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		err := os.Mkdir(absPath, os.ModePerm)
		if err != nil {
			logging.GetLogger().Error().Msgf("create versionDir %s,err %v",absPath,err)
			return
		}
	}

	m.Versions = absPath

	if action == ActionUp {
		// m.Upgrade(uint(steps))
		m.Upgrade()
	} else if action == ActionDown {
		// m.Downgrade(uint(steps))
		m.Downgrade()
	} else if action == ActionNew {
		var now = time.Now()
		var timeStr = now.Format("20060102150405")
		title, err := cmd.Flags().GetString("title")
		if len(title) == 0 {
			logging.GetLogger().Error().Msg("title should not be empty when create new migrate file")
			return
		}

		var shortTitle string
		if err != nil {
			logging.GetLogger().Error().Msgf("error while parsing params title",err)
			return
		}
		if len(title) > MaxTitleLen {
			shortTitle = title[:MaxTitleLen]
		} else {
			shortTitle = title
		}
		shortTitle = strings.ToLower(strings.Replace(shortTitle, " ", "-", -1))
		var up = fmt.Sprintf("%s/%s_%s.up.sql", absPath, timeStr, shortTitle)
		var down = fmt.Sprintf("%s/%s_%s.down.sql", absPath, timeStr, shortTitle)
		upFile, err := os.Create(up)
		if err != nil {
			logging.GetLogger().Error().Msgf("Error while creating migration up file,%s,err %v",up,err)
			return
		}
		downFile, err := os.Create(down)
		if err != nil {
			logging.GetLogger().Error().Msgf("Error while creating migration down file %s,%v",down,err)
			return
		}
		defer upFile.Close()
		defer downFile.Close()
		upFile.WriteString("-- " + title + " upgrade script")
		downFile.WriteString("-- " + title + " downgrade script")
		fmt.Printf("Migration file generated:\n  up: %s\n  down: %s\n", path.Base(up), path.Base(down))
	} else {
		var forceDown, err = cmd.Flags().GetBool("force-down")
		if err != nil {
			logging.GetLogger().Error().Msgf("Get flag failed %v",err)
		} else {
			if forceDown {
				m.ForceResetDown()
				return
			}
		}
		cmd.Help()
	}

}


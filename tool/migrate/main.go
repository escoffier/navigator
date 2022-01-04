package main

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func main() {
	var app = cli.App{
		Name:  "migration-tool",
		Usage: "migration tool",
		Commands: []*cli.Command{
			MigrateAccountCmd,
		},
		Version: "0.0.1",
	}

	var err = app.Run(os.Args)
	if err != nil {
		log.Fatalf("run fail, err:%s", err.Error())
	}
}

var MigrateAccountCmd = &cli.Command{
	Name:    "migrateAccount",
	Usage:   "migrate account",
	Aliases: []string{"MC"},
	Flags:   MigrateAccountFlags,
	Action:  MigrateAccount,
}

var MigrateAccountFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "mysqlDSN",
		Usage: "mysql dsn",
	},
	&cli.StringFlag{
		Name:  "pgDSN",
		Usage: "postgresql dsn",
	},
}

func MigrateAccount(c *cli.Context) error {
	mysqlDSN := c.String("mysqlDSN")
	pgDSN := c.String("pgDSN")

	mysqlDB, err := gorm.Open(mysql.Open(mysqlDSN), &gorm.Config{
		Logger: logger.Discard.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("new mysql db fail, err:%w", err)
	}

	pgDB, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{
		Logger: logger.Discard.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("new postgresql db fail, err:%w", err)
	}

	type migration func(pgDB, mysqlDB *gorm.DB) error
	var migrations = []migration{
		migrateUsers,
		migrateUrls,
		migrateModules,
		migrateOpenAPITokens,
		migrateLdapGroups,
	}
	for _, f := range migrations {
		if err := f(pgDB, mysqlDB); err != nil {
			return err
		}
	}

	return nil
}

func migrateUsers(pgDB, mysqlDB *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var users []*model.User
	var err = pgDB.WithContext(ctx).Table("tensor_user").Find(&users).Error
	if err != nil {
		return err
	}

	if len(users) == 0 {
		return nil
	}

	return mysqlDB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).CreateInBatches(users, 100).Error
}

func migrateUrls(pgDB, mysqlDB *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var urls []*model.Url
	var err = pgDB.WithContext(ctx).Table("tensor_url").Find(&urls).Error
	if err != nil {
		return err
	}
	if len(urls) == 0 {
		return nil
	}

	return mysqlDB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).CreateInBatches(urls, 100).Error

}

func migrateModules(pgDB, mysqlDB *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var modules []*model.ModuleGroup
	var err = pgDB.WithContext(ctx).Table("tensor_module").Find(&modules).Error
	if err != nil {
		return err
	}
	if len(modules) == 0 {
		return nil
	}

	return mysqlDB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).CreateInBatches(modules, 100).Error
}

func migrateOpenAPITokens(pgDB, mysqlDB *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var tokens []*model.OpenAPIAuthToken
	var err = pgDB.WithContext(ctx).Table("openapi_auth_token").Find(&tokens).Error
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return nil
	}

	return mysqlDB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).CreateInBatches(tokens, 100).Error
}

func migrateLdapGroups(pgDB, mysqlDB *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var groups []*model.LdapGroup
	var err = pgDB.WithContext(ctx).Table("ldap_groups").Find(&groups).Error
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		return nil
	}

	return mysqlDB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).CreateInBatches(groups, 100).Error
}

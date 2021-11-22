package main

import (
	"context"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

func main() {
	var app = cli.App{
		Name:  "db-init",
		Usage: "init db",
		Commands: []*cli.Command{
			InitTablesCmd,
		},
		Version: "0.0.1",
	}

	var err = app.Run(os.Args)
	if err != nil {
		log.Fatalf("run fail, err:%s", err.Error())
	}
}

var InitTablesCmd = &cli.Command{
	Name:    "InitTables",
	Usage:   "init tables",
	Aliases: []string{"IT"},
	Flags:   InitTablesFlags,
	Action:  InitTables,
}

var InitTablesFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "pgDSN",
		Usage: "postgresql dsn",
	},
}

func InitTables(c *cli.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pgDSN := c.String("pgDSN")

	db, err := rdbtools.NewPostgresClient(pgDSN)
	if err != nil {
		return err
	}

	return db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Exec(sql).Error
	})
}

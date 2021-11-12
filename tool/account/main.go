package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func main() {
	var app = cli.App{
		Name:  "account-tool",
		Usage: "account tool",
		Commands: []*cli.Command{
			AddUserCmd,
			ShowModulesCmd,
		},
		Version: "0.0.1",
	}

	var err = app.Run(os.Args)
	if err != nil {
		log.Fatalf("run fail, err:%s", err.Error())
	}
}

var AddUserCmd = &cli.Command{
	Name:    "addUser",
	Usage:   "add user",
	Aliases: []string{"AU"},
	Flags:   AddUserFlags,
	Action:  AddUser,
}

var AddUserFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "username",
		Usage: "username",
	},
	&cli.StringFlag{
		Name:  "password",
		Usage: "user password",
	},
	&cli.StringFlag{
		Name:  "role",
		Usage: "user role, support normal/admin/super-admin",
	},
	&cli.StringSliceFlag{
		Name:  "moduleID",
		Usage: "user module id list",
	},
	&cli.StringFlag{
		Name:  "pgDSN",
		Usage: "postgresql dsn",
	},
}

func AddUser(c *cli.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	pgDSN := c.String("pgDSN")
	username := c.String("username")
	password := c.String("password")
	role := c.String("role")
	moduleIDs := c.StringSlice("moduleID")
	moduleIDs = util.FilterDuplicateStringArray(moduleIDs)

	if username == "" || password == "" {
		return fmt.Errorf("empty username or password")
	}

	if role != model.RoleNormal && role != model.RoleAdmin && role != model.RoleSuperAdmin {
		return fmt.Errorf("invalid role")
	}

	db, err := rdbtools.NewPostgresClient(pgDSN)
	if err != nil {
		return err
	}

	modules, err := dal.GetAllModules(ctx, db)
	if err != nil {
		return err
	}

	moduleHash := make(map[string]struct{})
	for _, module := range modules {
		moduleHash[strconv.Itoa(module.Id)] = struct{}{}
	}

	for _, moduleID := range moduleIDs {
		if _, ok := moduleHash[moduleID]; !ok {
			return fmt.Errorf("invalid moduleID:%s", moduleID)
		}
	}

	return db.Get().Transaction(func(tx *gorm.DB) error {
		innerErr := dal.InsertUser(ctx, tx, username, role, moduleIDs)
		if innerErr != nil {
			if util.IsPostgresDuplicateError(innerErr) {
				return fmt.Errorf("username exists:%s", username)
			}
			return innerErr
		}

		return dal.ActiveUser(ctx, tx, username, password)
	})
}

var ShowModulesCmd = &cli.Command{
	Name:    "showModules",
	Usage:   "show modules",
	Aliases: []string{"SM"},
	Flags:   ShowModulesFlags,
	Action:  ShowModules,
}

var ShowModulesFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "pgDSN",
		Usage: "postgresql dsn",
	},
}

func ShowModules(c *cli.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	pgDSN := c.String("pgDSN")
	db, err := rdbtools.NewPostgresClient(pgDSN)
	if err != nil {
		return err
	}

	modules, err := dal.GetAllModules(ctx, db)
	if err != nil {
		return err
	}

	for _, module := range modules {
		log.Printf("id:%d, enName:%s, zhName:%s\n", module.Id, module.ModuleNameEn, module.ModuleNameZh)
	}

	return nil
}

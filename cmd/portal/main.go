package main

import (
	"flag"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/api"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/config"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/service"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	_ "go.uber.org/automaxprocs"
)

func main() {
	configPath := ""
	flag.StringVar(&configPath, "config-path", "config.yaml", "")

	flag.Parse()

	cfg, err := config.ParseConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("can not parse config:%s", err.Error()))
	}

	instance := store.NewRDBInstance()
	if instance == nil {
		panic("can not connect database")
	}
	if cfg.Portal.LogLevel == "debug" {
		instance.SetDebugMode()
	}
	ciUserDal := imagesecStore.NewUserDao(instance)
	portalUserDal := store.NewUserStore(instance)
	useS := service.NewUserService(store.NewUserStore(instance))
	proS := service.NewProjectService(store.NewProjectStore(instance))
	ciDal := adaptStore.NewCiDao(instance)

	ciDalSrv := ci.NewCiComponent(ciDal, ciUserDal)
	router := api.NewAPi(useS, portalUserDal, proS, ciDalSrv)
	if err := router.Run(cfg.Portal.Addr); err != nil {
		panic("can not start api sever")
	}
}

/*
--log-level=debug --codesec-url=http://1.95.60.107:28081 --source-check-url=http://1.95.46.47:30000
--codesec-ak=a6dd7669-e5af-467d-9550-97a81f1a2756
--codesec-sk=eyJhbGciOiJIUzUxMiJ9.eyJub25jZSI6IjlkNTlhZDMyLTBhMzItNDAyNC04YjQ0LTYyZDUyOGY0Yzc3YiIsInN1YiI6IjdiMjE0NTcyLTRmMWQtNDYzMC1iYTczLTEyNzMxZWNmZGYwMiJ9.MbTQcgp_lzRq6ejwstlLoOsfgZkkEbwSbF08CfSBNbDSpPosCHD8zF7-a-yiFE8j6P_E_I-u-Nb2JElW47zCJA
--source-check-token=b3JnYWRtaW5Ac2Vjem9uZS5jbjpkYWEwZjE0MzE5NzA0MWNlYTEzYmZkMWUyOGQwMDM3Yg==
*/

package dbManage

// import (
// 	"fmt"
//
// 	"github.com/gin-gonic/gin"
// 	"gitlab.com/security-rd/go-pkg/logging"
//
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
// 	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
// 	"gitlab.com/piccolo_su/vegeta/pkg/response"
// )
//
// type DBManageSrv struct {
// 	Srv DBManage
// }
//
// func NewDBManageSrv(dal store.VersionDal, useDal imagesecStore.UserDal) DBManageSrv {
// 	return DBManageSrv{NewDBManage(dal, useDal)}
// }
//
// func (d *DBManageSrv) UploadVulnOffline(ctx *gin.Context) {
// 	logging.Get().Info().Msg("in uploadOffline")
// 	updater := ctx.Query("updater")
// 	header, err := ctx.FormFile("file")
// 	if err != nil {
// 		logging.Get().Err(err).Msg("ParseMultipartForm fail")
// 		response.JSONError(ctx, fmt.Errorf("解析MultipartForm失败"))
// 		return
// 	}
// 	err = d.Srv.UpdateVulnDB(ctx, header, updater)
// 	if err != nil {
// 		logging.Get().Err(err).Msg("UpdateVulnDB error")
// 		response.JSONError(ctx, fmt.Errorf("更新漏洞库失败"))
// 		return
// 	}
// 	response.JSONOK(ctx)
// }
//
// func (d *DBManageSrv) UploadMaliciousOffline(ctx *gin.Context) {
// 	logging.Get().Info().Msg("in uploadMaliciousOffline")
// 	updater := ctx.Query("updater")
// 	header, err := ctx.FormFile("file")
// 	options := ctx.Query("options")
// 	if err != nil {
// 		logging.Get().Err(err).Msg("ParseMultipartForm fail")
// 		response.JSONError(ctx, fmt.Errorf("解析MultipartForm失败"))
// 		return
// 	}
// 	err = d.Srv.UpdateMaliciousDB(ctx, header, updater, options)
// 	if err != nil {
// 		logging.Get().Err(err).Msg("UpdateMaliciousDB error")
// 		response.JSONError(ctx, fmt.Errorf("更病毒库库失败"))
// 		return
// 	}
// 	response.JSONOK(ctx)
// }
//
// func (d *DBManageSrv) GetVersion(ctx *gin.Context) {
// 	search := ctx.Query("search")
// 	res, err := d.Srv.GetDBVersion(ctx, search)
// 	if err != nil {
// 		logging.Get().Err(err).Msg("GetDBVersion error")
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	response.JSONOK(ctx, response.WithItems(res))
// }
//
// func (d *DBManageSrv) GetHistory(ctx *gin.Context) {
// 	search := ctx.Query("version")
// 	dbType := ctx.Query("dbType")
// 	res, err := d.Srv.GetHistory(ctx, search, dbType)
// 	if err != nil {
// 		logging.Get().Err(err).Msg("GetHistory error")
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	response.JSONOK(ctx, response.WithItems(res))
// }

package api

import (
	"bytes"
	"io"
	"strconv"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type DbManagerAPISrv struct {
	DBManagerSrv imagesecSrv.DBManagerService
}

func NewDBManagerAPISrv(dBManagerSrv imagesecSrv.DBManagerService) *DbManagerAPISrv {
	return &DbManagerAPISrv{DBManagerSrv: dBManagerSrv}
}

func (s *DbManagerAPISrv) UpdateDb(ctx *gin.Context) {
	logging.Get().Info().Msg("update db")

	updater := util.GetKeywordFromQuery(ctx, "updater")
	dbType := util.GetKeywordFromQuery(ctx, "dbType")

	header, err := ctx.FormFile("file")
	if err != nil {
		response.JSONError(ctx, scani18.ParseDbFileErr(err))
		return
	}
	open, err := header.Open()
	if err != nil {
		response.JSONError(ctx, scani18.ParseDbFileErr(err))
		return
	}
	data, err := StreamToByte(open)
	if err != nil {
		response.JSONError(ctx, scani18.ParseDbFileErr(err))
		return
	}
	param := imagesecModel.UpdateDbParam{
		Updater: updater,
		DbType:  dbType,
		Data:    data,
	}
	if err := s.DBManagerSrv.UpdateDB(ctx, param); err != nil {
		response.JSONError(ctx, scani18.SaveDbFileErr(err))
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(0), Name: dbType}))
}

func StreamToByte(stream io.ReadCloser) ([]byte, error) {
	defer func() { _ = stream.Close() }()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(stream)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

package scanwebshell

import (
	"archive/tar"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

type WebshellController struct {
	dal store.WebshellDalInterface
	Srv WebshellSrv
}

func NewWebshellComponent(dal store.WebshellDalInterface) WebshellController {
	return WebshellController{dal: dal, Srv: NewWebshellSrv(dal)}
}
func (w *WebshellController) GetParseInt(ctx *gin.Context, s string) int64 {
	str := ctx.Query(s)
	if str == "" {
		return 0
	}
	num, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		logging.Get().Err(err).Msgf("Parse %v error str :%v", s, str)
		return 0
	}
	return num
}
func (w *WebshellController) ListWebshell(ctx *gin.Context) {
	limit := w.GetParseInt(ctx, "limit")
	offset := w.GetParseInt(ctx, "offset")
	imageID := w.GetParseInt(ctx, "imageID")
	search := ctx.Query("keyword")
	layerDigest := ctx.Query("layer_digest")
	if imageID == 0 {
		logging.Get().Error().Msg("image_id is 0")
		response.JSONError(ctx, fmt.Errorf("imageID can't be 0"))
		return
	}
	webshells, cnt, err := w.Srv.ListWebshells(ctx, store.SearchWebshellParam{ImageID: imageID, Search: search, LayerDigest: layerDigest}, model.Filter{Limit: limit, Offset: offset})
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("get webshell list error"))
		return
	}
	response.JSONOK(ctx, response.WithItems(webshells), response.WithTotalItems(cnt))
}

func (w *WebshellController) GetWebshellDetail(ctx *gin.Context) {
	uuidStr := ctx.Query("uuid")
	uuid, err := strconv.ParseUint(uuidStr, 10, 64)
	if err != nil {
		logging.Get().Err(err).Msg("parse uuid error")
		response.JSONError(ctx, fmt.Errorf("parse uuid error"))
		return
	}
	webshell, err := w.Srv.GetDetail(ctx, store.SearchWebshellParam{UUIDS: []uint64{uuid}}, model.Filter{})
	if err != nil {
		logging.Get().Err(err).Msgf("get webshell detail error uuid %d", uuid)
		response.JSONError(ctx, fmt.Errorf("get webshell detail error uuid %d", uuid))
		return
	}
	response.JSONOK(ctx, response.WithItem(webshell))
}

func (w *WebshellController) Download(ctx *gin.Context) {
	md5 := ctx.Query("md5")
	uuidStr := ctx.Query("uuid")
	uuid, err := strconv.ParseUint(uuidStr, 10, 64)
	if err != nil {
		logging.Get().Err(err).Msg("parse uuid error")
		response.JSONError(ctx, fmt.Errorf("parse uuid error"))
		return
	}
	pro, err := w.Srv.GetCode(md5, uuid)
	if err != nil {
		logging.Get().Err(err).Msg("get problem code error")
		response.JSONError(ctx, fmt.Errorf("get problem code error"))
		return
	}
	response.JSONOK(ctx, response.WithItems(pro))
}

func (w *WebshellController) GetFile(ctx *gin.Context) {
	md5 := ctx.Query("fileMd5")
	filePath := filepath.Join("/root/webshell", md5)
	TarPath := filepath.Join("/root/webshell", fmt.Sprintf("%s.tar", md5))
	res := Tar(filePath, TarPath)
	switch res.(type) {
	case error:
		response.JSONError(ctx, fmt.Errorf("file can't tar"))
		return
	}
	if util.FileExists(TarPath) {
		defer os.Remove(TarPath)
		result, err := os.ReadFile(TarPath)
		if err != nil {
			response.JSONError(ctx, fmt.Errorf("file not exist"))
			return
		}
		ctx.Writer.WriteHeader(http.StatusOK)
		ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", md5))
		ctx.Header("Content-Type", "application/octet-stream")
		ctx.Header("Accept-Length", strconv.Itoa(len(result)))
		_, _ = ctx.Writer.Write(result)
	} else {
		response.JSONError(ctx, fmt.Errorf("file not exist"))
	}
}

func Tar(unTarFileName string, tarFileName string) interface{} {
	// 打开源文件
	sourceFile, err := os.Open(unTarFileName)
	defer sourceFile.Close()
	if err != nil {
		return err
	}
	/* 向 tar 文件中写入数据是通过 tar.Writer 完成的，所以首先要创建 tar.Writer，
	可以通过 tar.NewWriter 方法来创建它，该方法要求提供一个 os.Writer 对象，
	以便将打包后的数据写入该对象中。
	可以先创建一个文件，然后将该文件提供给 tar.NewWriter 使用。
	*/
	// 创建文件用于储存打包后的数据
	destinationFile, err := os.Create(tarFileName)
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	/* 创建tar.Writer对象.此时，我们就拥有了一个 tar.Writer 对象 tw，可以用它来打包文件了。
	这里要注意一点，使用完 tw 后，一定要执行 tw.Close() 操作，
	因为 tar.Writer 使用了缓存，tw.Close() 会将缓存中的数据写入到文件中，
	同时 tw.Close() 还会向 .tar 文件的最后写入结束信息，如果不关闭 tw 而直接退出程序，
	那么将导致 .tar 文件不完整。
	存储在 .tar 文件中的每个文件都由两部分组成：文件头信息和文件内容，
	所以向 .tar 文件中写入每个文件都要分两步：
	第一步写入文件信息，第二步写入文件数据。
	对于目录来说，由于没有内容可写，所以只需要写入目录信息即可。
	*/
	tw := tar.NewWriter(destinationFile)
	defer tw.Close()
	// 获取源文件信息
	sourceFileInfo, err := os.Stat(unTarFileName)
	if err != nil {
		return err
	}
	// 根据 os.FileInfo创建tar.Header信息头
	hdr, err := tar.FileInfoHeader(sourceFileInfo, "")
	// 第一步写入头文件信息,通过tw.WriteHeader方法将hdr写入.tar文件中
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	// 第二部,写入数据
	_, err = io.Copy(tw, sourceFile)
	if err != nil {
		return err
	}
	return true
}

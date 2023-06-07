package response

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	DuplicateKey = "Duplicate"
	LangEN       = "en"
)

type I18Err struct {
	Code int64  `json:"code"`
	Msg  string `json:"msg"`
	Ch   string `json:"ch"`
	En   string `json:"en"`
}

func (vi I18Err) Error() string {
	return vi.Msg
}

func (vi I18Err) getErr(ctx *gin.Context) error {
	lang := util.GetLanguage(ctx)
	if lang == LangEN {
		return fmt.Errorf(vi.En)
	}
	return fmt.Errorf(vi.Ch)
}

func SearchErr(err error) I18Err {
	vi := I18Err{}

	if err == nil {
		return vi
	}
	vi.Msg = err.Error()
	vi.Code = http.StatusBadRequest

	vi.Ch = fmt.Sprintf("查询出错")
	vi.En = fmt.Sprintf("search error")

	return vi
}

func UpdateErr(err error) I18Err {
	vi := I18Err{}
	if err == nil {
		return vi
	}
	vi.Msg = err.Error()
	vi.Code = http.StatusBadRequest
	vi.Ch = fmt.Sprintf("更新出错")
	vi.En = fmt.Sprintf("update error")

	return vi
}

func DeleteErr(err error) I18Err {
	vi := I18Err{}
	if err == nil {
		return vi
	}
	vi.Msg = err.Error()
	vi.Code = http.StatusBadRequest
	vi.Ch = fmt.Sprintf("删除出错")
	vi.En = fmt.Sprintf("delete error")

	return vi
}

func CreateErr(err error) I18Err {
	vi := I18Err{}

	if err == nil {
		return vi
	}
	vi.Code = http.StatusBadRequest
	vi.Msg = err.Error()
	if strings.Contains(err.Error(), DuplicateKey) {
		vi.Ch = fmt.Sprintf("已存在同名资源")
		vi.En = fmt.Sprintf("the name already exists")
		return vi
	}

	vi.Ch = fmt.Sprintf("创建出错")
	vi.En = fmt.Sprintf("create error")

	return vi
}

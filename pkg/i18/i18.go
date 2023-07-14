package i18

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

type ErrI18 struct {
	Code int64  `json:"code"`
	Err  error  `json:"err"`
	Ch   string `json:"ch"`
	En   string `json:"en"`
}

func CreateI18BadReqErr(ch, en string) *ErrI18 {
	return &ErrI18{
		Code: http.StatusBadRequest,
		Ch:   ch,
		En:   en,
		Err:  fmt.Errorf(en),
	}
}

func (vi *ErrI18) Error() string {
	if vi == nil {
		return ""
	}
	if vi.Err != nil {
		return vi.Err.Error()
	}
	if vi.En != "" {
		return vi.En
	}
	if vi.Ch != "" {
		return vi.Ch
	}
	return ""
}

func (vi *ErrI18) GetGinErr(ctx *gin.Context) error {
	if vi == nil {
		return nil
	}

	lang := util.GetLanguage(ctx)
	if lang == LangEN {
		return fmt.Errorf(vi.En)
	}
	return fmt.Errorf(vi.Ch)
}

func assertion(err error) (*ErrI18, bool) {
	if e1, ok := err.(*ErrI18); ok && e1 != nil {
		return e1, true
	}
	return nil, false
}

func SearchErr(err error) *ErrI18 {
	if e, ok := assertion(err); ok {
		return e
	}

	vi := &ErrI18{Err: err}

	if err == nil {
		return vi
	}
	vi.Code = http.StatusBadRequest

	vi.Ch = fmt.Sprintf("查询出错")
	vi.En = fmt.Sprintf("search error")

	return vi
}

func UpdateErr(err error) *ErrI18 {
	if e, ok := assertion(err); ok {
		return e
	}
	vi := &ErrI18{Err: err}
	if err == nil {
		return vi
	}
	vi.Code = http.StatusBadRequest
	vi.Ch = fmt.Sprintf("更新出错")
	vi.En = fmt.Sprintf("update error")

	return vi
}

func DeleteErr(err error) *ErrI18 {
	if e, ok := assertion(err); ok {
		return e
	}
	vi := &ErrI18{Err: err}
	if err == nil {
		return vi
	}
	vi.Code = http.StatusBadRequest
	vi.Ch = fmt.Sprintf("删除出错")
	vi.En = fmt.Sprintf("delete error")

	return vi
}

func CreateErr(err error) *ErrI18 {
	if e, ok := assertion(err); ok {
		return e
	}
	vi := &ErrI18{Err: err}

	if err == nil {
		return nil
	}
	vi.Code = http.StatusBadRequest
	if strings.Contains(err.Error(), DuplicateKey) {
		vi.Ch = fmt.Sprintf("已存在同名资源")
		vi.En = fmt.Sprintf("the name already exists")
		return vi
	}

	vi.Ch = fmt.Sprintf("创建出错")
	vi.En = fmt.Sprintf("create error")

	return vi
}

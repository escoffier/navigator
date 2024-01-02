package imagesec

import (
	"math"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

type Filter struct {
	// 如果只有一项排序可以写在SortBy和SortFiled这两个字段中，
	SortBy    string `json:"sort_by"`
	SortFiled string `json:"sort_filed"`

	// 如果是多行或指义的排列，就写入OrderByColumns字段中
	OrderByColumns []clause.OrderByColumn

	Offset int64 `json:"offset"`
	Limit  int64 `json:"limit"`
}

func (f *Filter) SetSortCreatedAt() *Filter {
	af := f.DeepCopy()
	af.SortFiled = "created_at"
	return af
}

func (f *Filter) SetSortDesc() *Filter {
	af := f.DeepCopy()
	af.SortBy = consts.SortByDesc
	return af
}

func (f *Filter) SetSortAsc() *Filter {
	af := f.DeepCopy()
	af.SortBy = consts.SortByAsc
	return af
}

func (f *Filter) SetSortFiledByID() *Filter {
	return f.DeepCopy().SetSortFiled("id")
}

func (f *Filter) SetLimit(limit int64) *Filter {
	af := f.DeepCopy()
	af.Limit = limit
	return af
}

func (f *Filter) SetMaxLimit(limit int64) *Filter {
	af := f.DeepCopy()

	if af.Limit > limit || af.Limit <= 0 {
		af.Limit = limit
	}
	return af
}

func (f *Filter) SetOffset(offset int64) *Filter {
	af := f.DeepCopy()
	af.Offset = offset
	return af
}

func (f *Filter) SetSortFiled(sortFiled string) *Filter {
	af := f.DeepCopy()
	af.SortFiled = sortFiled
	return af
}

func EmptyFilter() *Filter {
	return &Filter{}
}

func GetFilter(ctx *gin.Context) *Filter {
	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	sortBy := ctx.Query("sort_by")
	sortFiled := ctx.Query("sort_filed")
	if limit <= 0 {
		limit = math.MaxInt32 // 说明取全部数据
	}

	if offset <= 0 {
		offset = 0
	}

	filter := &Filter{Offset: offset, Limit: limit, SortBy: sortBy, SortFiled: sortFiled}
	filter.OrderByColumns = make([]clause.OrderByColumn, 0)
	return filter
}

func GetFilterWithDefaultValue(ctx *gin.Context) *Filter {
	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	sortBy := ctx.Query("sort_by")
	sortFiled := ctx.Query("sort_filed")

	filter := &Filter{Offset: offset, Limit: limit, SortBy: sortBy, SortFiled: sortFiled}
	filter.OrderByColumns = make([]clause.OrderByColumn, 0)
	filter = filter.SetDefault()
	return filter
}

func EmptyFilterForTotalQuery() *Filter {
	return &Filter{
		Offset:    0,
		Limit:     math.MaxInt32,
		SortBy:    "desc",
		SortFiled: "id",
	}
}

func (f *Filter) SetDefault() *Filter {
	if f == nil {
		return &Filter{
			Offset:    0,
			Limit:     math.MaxInt64,
			SortBy:    "desc",
			SortFiled: "id",
		}
	}
	if f.SortBy != "" {
		f.SortBy = strings.ToLower(f.SortBy)
	} else {
		f.SortBy = "desc"
	}

	if f.SortBy == "" || (f.SortBy != "desc" && f.SortBy != "asc") {
		f.SortBy = "desc"
	}

	if f.Offset <= 0 {
		f.Offset = 0 // 取第一页
	}
	if f.Limit <= 0 {
		f.Limit = 10 // 不传就返一条数据，尽早发现问题
	}
	return f
}

func (f *Filter) DeepCopy() *Filter {
	if f == nil {
		return &Filter{
			Limit: math.MaxInt32,
		}
	}
	res := Filter{
		SortBy:    f.SortBy,
		SortFiled: f.SortFiled,
		Offset:    f.Offset,
		Limit:     f.Limit,
	}
	return &res
}

func AddFilter(db *gorm.DB, filter *Filter) *gorm.DB {
	if filter != nil {
		if filter.Offset >= 0 && filter.Limit > 0 {
			db = db.Offset(int(filter.Offset)).Limit(int(filter.Limit))
		}
		if filter.SortFiled != "" && filter.SortBy != "" {
			db = db.Order(clause.OrderByColumn{Column: clause.Column{Name: filter.SortFiled}, Desc: strings.ToLower(filter.SortBy) == "desc"})
		}

		if filter.OrderByColumns != nil {
			for i := range filter.OrderByColumns {
				db = db.Order(filter.OrderByColumns[i])
			}
		}
	}
	// 这里如果是查全部，也给一个默认值，但是我们项目业务中有很多查全表数据的情况，所这里加这一项不合适
	// if filter == nil {
	// 	db = db.Limit(DefaultPageSize)
	// }
	return db
}

func AddFilterWithDefault(db *gorm.DB, filter *Filter) *gorm.DB {
	if filter == nil {
		filter = &Filter{Limit: 200}
	}

	if filter.Offset >= 0 && filter.Limit > 0 {
		db = db.Offset(int(filter.Offset)).Limit(int(filter.Limit))
	}
	if filter.SortFiled != "" && filter.SortBy != "" {
		db = db.Order(clause.OrderByColumn{Column: clause.Column{Name: filter.SortFiled}, Desc: strings.ToLower(filter.SortBy) == "desc"})
	}

	if filter.OrderByColumns != nil {
		for i := range filter.OrderByColumns {
			db = db.Order(filter.OrderByColumns[i])
		}
	}
	return db
}

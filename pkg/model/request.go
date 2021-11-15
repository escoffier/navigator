package model

type PageParams struct {
	Offset int `json:"offset" query:"offset" form:"offset"`
	Limit  int `json:"limit" query:"limit" form:"limit" binding:"required"`
}

type ID struct {
	ID uint `uri:"id" binding:"required" json:"id"`
}

package model

import "time"

type OpenAPIAuthToken struct {
	ID        int32     `gorm:"column:id"`                                                   // primary key, autoIncrement
	Token     string    `gorm:"column:token; index:open_api_auth_token_token, unique"`       // unique
	Username  string    `gorm:"column:username; index:open_api_auth_token_username, unique"` // unique
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
	Status    int       `gorm:"column:status"`
}

func (OpenAPIAuthToken) TableName() string {
	return "openapi_auth_token"
}
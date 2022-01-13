package model

import "gorm.io/gorm"

type SqlBuilder interface {
	SqlBuild(*gorm.DB) *gorm.DB
}

type Option func(*gorm.DB) *gorm.DB

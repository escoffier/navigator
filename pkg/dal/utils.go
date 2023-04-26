package dal

import "gorm.io/gorm"

type QueryBuilderFunc func(db *gorm.DB) (built *gorm.DB)

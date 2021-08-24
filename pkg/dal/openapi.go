package dal

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func GetUserAuthTokenByUsername(ctx context.Context, db *gorm.DB, username string) (*model.OpenAPIAuthToken, bool, error) {
	var token model.OpenAPIAuthToken
	var err = db.WithContext(ctx).Where("username = ?", username).First(&token).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false, nil
		}

		return nil, false, err
	}

	return &token, true, nil
}

func GetUserByToken(ctx context.Context, db *gorm.DB, authToken string) (*model.User, bool, error) {
	var token model.OpenAPIAuthToken
	var err = db.WithContext(ctx).Where("token = ?", authToken).First(&token).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false, nil
		}

		return nil, false, err
	}

	ok, user, err := SelectUser(ctx, db, token.Username)
	return user, ok, err
}

func SaveAuthToken(ctx context.Context, db *gorm.DB, username, token string) error {
	authToken := &model.OpenAPIAuthToken{
		Username:  username,
		Token:     token,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return db.WithContext(ctx).Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "username"}},
			DoNothing: true,
		},
	).Create(authToken).Error
}

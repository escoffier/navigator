package store

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type TrustedImageInterface interface {
	SearchTrustedImages(ctx context.Context, param SearchTrustedImageParam) ([]model.TrustedImages, error)
	TrustedImageCreat(ctx context.Context, trustedImage *model.TrustedImages) error

	ImageRsaCreate(ctx context.Context, data *model.ImageRsa) error
	ImageRsaUpdate(ctx context.Context, id int64, data *model.ImageRsa) error
	ImageRsaDetail(ctx context.Context, id int64) (*model.ImageRsa, error)
	ImageRsaDelete(ctx context.Context, id int64) error
	ImageRsaList(ctx context.Context, limit, offset int64) ([]model.ImageRsa, int64, error)
	ImageRsaQueryByPrivateKey(ctx context.Context, privateKey string) (*model.ImageRsa, error)
}

// SearchTrustedImages 获取多个镜像的可信信息,可能需要查询全部
func (s *ScannerOrm) SearchTrustedImages(ctx context.Context, param SearchTrustedImageParam) ([]model.TrustedImages, error) {
	timeOutCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	var result = make([]model.TrustedImages, 0)

	db := s.psql.Get().WithContext(timeOutCtx).Model(model.TrustedImages{})
	if len(param.Digests) > 0 {
		db = db.Where("digest IN ?", param.Digests)
	}
	if param.IsTrusted == consts.IsTrustedImageString {
		db = db.Where("is_trusted = ? ", consts.IsTrustedImage)
	} else if param.IsTrusted == consts.NotTrustedImageString {
		db = db.Where("is_trusted = ? ", consts.NotTrustedImage)
	}

	if err := db.Find(&result).Error; err != nil {
		return nil, err
	}
	return result, nil
}

func (s *ScannerOrm) TrustedImageCreat(ctx context.Context, trustedImage *model.TrustedImages) error {
	return s.psql.Get().WithContext(ctx).Create(trustedImage).Error
}

func (s *ScannerOrm) ImageRsaCreate(ctx context.Context, data *model.ImageRsa) error {
	return s.psql.Get().WithContext(ctx).Create(data).Error
}

func (s *ScannerOrm) ImageRsaDetail(ctx context.Context, id int64) (*model.ImageRsa, error) {
	data := new(model.ImageRsa)
	err := s.psql.Get().WithContext(ctx).Model(data).Where("id = ?", id).First(data).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("暂无id<%d>数据", id)
		} else {
			return nil, errors.Wrapf(err, "查询Id:<%d>失败", id)
		}
	}

	return data, nil
}

func (s *ScannerOrm) ImageRsaDelete(ctx context.Context, id int64) error {
	err := s.psql.Get().WithContext(ctx).Delete(&model.ImageRsa{}, id).Error
	if err != nil {
		return errors.Wrapf(err, "删除ID:<%d>失败", id)
	}
	return nil
}

func (s *ScannerOrm) ImageRsaList(ctx context.Context, limit, offset int64) ([]model.ImageRsa, int64, error) {
	var (
		err   error
		count int64
	)

	if err := s.psql.Get().WithContext(ctx).Model(model.ImageRsa{}).Count(&count).Error; err != nil {
		return nil, 0, err
	}

	var r = make([]model.ImageRsa, 0, limit)

	err = s.psql.Get().
		Model(model.ImageRsa{}).
		Limit(int(limit)).
		Offset(int(offset)).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "created_at"}, Desc: true}).
		Find(&r).
		Error
	if err != nil {
		return nil, 0, err
	}

	return r, count, nil
}

func (s *ScannerOrm) ImageRsaQueryByPrivateKey(ctx context.Context, privateKey string) (*model.ImageRsa, error) {
	var data model.ImageRsa
	err := s.psql.Get().WithContext(ctx).Where("private_key_digest = ?", privateKey).First(&data).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.Wrapf(err, "暂无私钥<%s>数据", privateKey)
		} else {
			return nil, errors.Wrapf(err, "私钥<%s>查询失败", privateKey)
		}
	}

	return &data, err
}

func (s *ScannerOrm) ImageRsaUpdate(ctx context.Context, id int64, data *model.ImageRsa) error {

	m := map[string]interface{}{
		"name":       data.Name,
		"registry":   data.Registry,
		"match_rule": data.MatchRule,
		"comment":    data.Comment,
	}

	db := s.psql.Get().
		WithContext(ctx).
		Model(data).
		Where("id = ?", id).
		Updates(m)

	if err := db.Error; err != nil {
		return errors.Wrap(err, "更新失败")
	}

	if db.RowsAffected == 0 {
		return errors.New("更新失败，暂无此条数据")
	}

	return nil
}

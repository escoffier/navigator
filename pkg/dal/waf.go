package dal

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	onDupUpdatedColsForWaf = []string{
		"name",
		"mode",
		"uri_prefix",
		"description",
		"updated_at",
	}
)

type ColMultiQuery struct {
	column string
	query  []string
}

type ServiceQueryOption struct {
	WhereLikeCondition map[string]string
	whereEqCondition   map[string]interface{}
	columnQueries      []colMultiQuery
	whereInCondition   map[string]interface{}
}

func ServiceQuery() *ServiceQueryOption {
	return &ServiceQueryOption{
		WhereLikeCondition: map[string]string{},
		whereEqCondition:   map[string]interface{}{},
		whereInCondition:   make(map[string]interface{}, 3),
	}
}

func (n *ServiceQueryOption) WithFuzzyCluster(clusterKey string) *ServiceQueryOption {
	n.WhereLikeCondition["cluster_key"] = clusterKey
	return n
}

func (n *ServiceQueryOption) WithFuzzyName(name string) *ServiceQueryOption {
	n.WhereLikeCondition["name"] = name
	return n
}

func (n *ServiceQueryOption) WithFuzzyHost(host string) *ServiceQueryOption {
	n.WhereLikeCondition["host"] = host
	return n
}

func (n *ServiceQueryOption) WithFuzzyResource(resource string) *ServiceQueryOption {
	n.WhereLikeCondition["resource_name"] = resource
	return n
}

func (n *ServiceQueryOption) WithFuzzyNamespace(namespace string) *ServiceQueryOption {
	n.WhereLikeCondition["namespace"] = namespace
	return n
}

func (n *ServiceQueryOption) WithMode(ns string) *ServiceQueryOption {
	n.whereEqCondition["mode"] = ns
	return n
}

func (q *ServiceQueryOption) WithInConditionCustom(column string, value interface{}) *ServiceQueryOption {
	q.whereInCondition[column] = value
	return q
}

func (q *ServiceQueryOption) WithColumnMultiQuery(column string, query []string) *ServiceQueryOption {
	q.columnQueries = append(q.columnQueries, colMultiQuery{
		column: column,
		query:  query,
	})
	return q
}

func CreateWafService(ctx context.Context, rdb *gorm.DB, waf *model.WafService) (uint32, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	logging.GetLogger().Info().Msgf("upsert waf service %+v", waf)
	err := rdb.WithContext(oneCtx).Model(&model.WafService{}).Create(waf).Error
	if err != nil {
		return 0, err
	}
	return waf.ID, nil
}

func UpsertWafService(ctx context.Context, rdb *gorm.DB, waf *model.WafService) (uint32, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	waf.UpdatedAt = time.Now()
	logging.GetLogger().Info().Msgf("upsert waf service %+v", waf)
	err := rdb.WithContext(oneCtx).Model(&model.WafService{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForWaf),
	}).Create(waf).Error
	if err != nil {
		return 0, err
	}
	return waf.ID, nil
}

func GetWafService(ctx context.Context, rdb *gorm.DB, id uint32) (*model.WafService, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	waf := &model.WafService{}
	err := rdb.WithContext(oneCtx).Model(&model.WafService{}).Where("id = ?", id).First(waf).Error
	if err != nil {
		return waf, err
	}
	return waf, nil
}

func DeleteWafService(ctx context.Context, rdb *gorm.DB, id uint32) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	err := rdb.WithContext(oneCtx).Where("id = ?", id).Delete(&model.WafService{}).Error
	if err != nil {
		return err
	}
	return nil
}

func UpdatetServiceExpr(ctx context.Context, rdb *gorm.DB, ID, exprID uint32) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	// logging.GetLogger().Info().Msgf("upsert waf service %+v", waf)
	err := rdb.WithContext(oneCtx).Model(&model.WafService{}).Where("id = ?", ID).Update("expr_id", exprID).Error
	if err != nil {
		return err
	}
	return nil
}

func GetWafServices(ctx context.Context, rdb *gorm.DB, queryOpt *ServiceQueryOption, offset, limit int) (services []*model.WafService, err error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	db := rdb.WithContext(oneCtx).Model(&model.WafService{})

	if len(queryOpt.whereEqCondition) > 0 {
		db = db.Where(queryOpt.whereEqCondition)
	}
	for column, val := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
	}
	for column, val := range queryOpt.whereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}

	for _, c := range queryOpt.columnQueries {
		if len(c.query) > 0 {
			if len(c.query) == 1 {
				db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
				continue
			}
			subQuery := rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
			for _, q := range c.query[1:] {
				subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(q))
			}
			db = db.Where(subQuery)
		}
	}

	if limit > 0 && offset >= 0 {
		db = db.Offset(offset).Limit(limit)
	}
	err = db.Order("updated_at DESC").Find(&services).Error
	return
}

func CountWafServices(ctx context.Context, rdb *gorm.DB, queryOpt *ServiceQueryOption) (int64, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	db := rdb.WithContext(oneCtx).Model(&model.WafService{})

	if len(queryOpt.whereEqCondition) > 0 {
		db = db.Where(queryOpt.whereEqCondition)
	}
	for column, val := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
	}
	for column, val := range queryOpt.whereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}
	for _, c := range queryOpt.columnQueries {
		if len(c.query) > 0 {
			if len(c.query) == 1 {
				db = db.Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
				continue
			}
			subQuery := rdb.WithContext(oneCtx).Model(&model.TensorRawContainer{}).Where(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(c.query[0]))
			for _, q := range c.query[1:] {
				subQuery = subQuery.Or(fmt.Sprintf("%s LIKE ?", c.column), GetLikeExpr(q))
			}
			db = db.Where(subQuery)
		}
	}
	var cnt int64
	err := db.Count(&cnt).Error
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

type MatchExprQueryOption struct {
	WhereLikeCondition map[string]string
	whereEqCondition   map[string]interface{}
	columnQueries      []colMultiQuery
	whereInCondition   map[string]interface{}
}

func MatchExprQuery() *MatchExprQueryOption {
	return &MatchExprQueryOption{
		WhereLikeCondition: make(map[string]string, 3),
		whereEqCondition:   make(map[string]interface{}, 3),
		whereInCondition:   make(map[string]interface{}, 3),
	}
}

func (n *MatchExprQueryOption) WithFuzzyName(name string) *MatchExprQueryOption {
	n.WhereLikeCondition["name"] = name
	return n
}

func (n *MatchExprQueryOption) WithFuzzyExpr(expr string) *MatchExprQueryOption {
	n.WhereLikeCondition["expr"] = expr
	return n
}

func (n *MatchExprQueryOption) WithStatus(status int32) *MatchExprQueryOption {
	n.whereEqCondition["status"] = status
	return n
}

func (n *MatchExprQueryOption) WithMode(mode string) *MatchExprQueryOption {
	n.whereEqCondition["mode"] = mode
	return n
}

func (q *MatchExprQueryOption) WithColumnMultiQuery(column string, query []string) *MatchExprQueryOption {
	q.columnQueries = append(q.columnQueries, colMultiQuery{
		column: column,
		query:  query,
	})
	return q
}

func (q *MatchExprQueryOption) WithInConditionCustom(column string, value interface{}) *MatchExprQueryOption {
	q.whereInCondition[column] = value
	return q
}

func GetBlackWhiteList(ctx context.Context, rdb *gorm.DB, id uint32) (*model.MatcherExpr, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	expr := &model.MatcherExpr{}
	err := rdb.WithContext(oneCtx).Model(&model.MatcherExpr{}).Where("id = ?", id).First(expr).Error
	if err != nil {
		return expr, err
	}
	return expr, nil
}

func AddBlackWhiteList(ctx context.Context, rdb *gorm.DB, expr *model.MatcherExpr) (uint32, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	logging.GetLogger().Debug().Msgf("upsert blackwhite list %+v", expr)
	err := rdb.WithContext(oneCtx).Model(&model.MatcherExpr{}).Create(expr).Error
	if err != nil {
		return 0, err
	}
	return expr.ID, nil
}

func UpdateBlackWhiteList(ctx context.Context, rdb *gorm.DB, expr *model.MatcherExpr) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	logging.GetLogger().Debug().Msgf("upsert blackwhite list %+v", expr)
	err := rdb.WithContext(oneCtx).Model(&model.MatcherExpr{}).Where("id = ?", expr.ID).
		Updates(map[string]interface{}{"name": expr.Name, "scope": expr.Scope, "mode": expr.Mode, "expr": expr.Expr, "global": expr.Global, "status": expr.Status}).Error
	if err != nil {
		return err
	}
	return nil
}

func EnableBlackWhiteList(ctx context.Context, rdb *gorm.DB, id uint32, status int32) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	err := rdb.WithContext(oneCtx).Model(&model.MatcherExpr{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status}).Error
	if err != nil {
		return err
	}
	return nil
}

func DeleteBlackWhiteList(ctx context.Context, rdb *gorm.DB, id uint32) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()
	err := rdb.WithContext(oneCtx).Where("id = ?", id).Delete(&model.MatcherExpr{}).Error
	if err != nil {
		return err
	}
	return nil
}

func GetBlackWhiteLists(ctx context.Context, rdb *gorm.DB, queryOpt *MatchExprQueryOption, offset, limit int) (exprs []*model.MatcherExpr, err error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	db := rdb.WithContext(oneCtx).Model(&model.MatcherExpr{})

	if len(queryOpt.whereEqCondition) > 0 {
		db = db.Where(queryOpt.whereEqCondition)
	}
	for column, val := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
	}
	for column, val := range queryOpt.whereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}
	if limit > 0 && offset >= 0 {
		db = db.Offset(offset).Limit(limit)
	}
	err = db.Order("updated_at DESC").Find(&exprs).Error
	return
}

func CountBlackWhiteLists(ctx context.Context, rdb *gorm.DB, queryOpt *MatchExprQueryOption) (int64, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	db := rdb.WithContext(oneCtx).Model(&model.MatcherExpr{})

	if len(queryOpt.whereEqCondition) > 0 {
		db = db.Where(queryOpt.whereEqCondition)
	}
	for column, val := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", column), GetLikeExpr(val))
	}
	for column, val := range queryOpt.whereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}
	var cnt int64
	err := db.Count(&cnt).Error
	return cnt, err
}

func AddCerts(ctx context.Context, rdb *gorm.DB, key string, data []byte) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	cert := &model.WafCert{
		Key:     key,
		Content: data,
	}
	err := rdb.WithContext(oneCtx).Model(&model.WafCert{}).Create(cert).Error
	if err != nil {
		return err
	}
	return nil
}

func GetCerts(ctx context.Context, rdb *gorm.DB, crt, key string) ([]byte, []byte, error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer oneCancel()

	var crtData, KeyData model.WafCert
	err := rdb.WithContext(oneCtx).Model(&model.WafCert{}).Where("file_key = ?", crt).First(&crtData).Error
	if err != nil {
		return nil, nil, err
	}

	err = rdb.WithContext(oneCtx).Model(&model.WafCert{}).Where("file_key = ?", key).First(&KeyData).Error
	if err != nil {
		return nil, nil, err
	}
	return crtData.Content, KeyData.Content, nil
}

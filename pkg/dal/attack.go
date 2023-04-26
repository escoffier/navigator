package dal

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	tokenHeader               = "X-Tensorsec-cicd-key"
	token                     = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
	queryKeyCurDataVersion    = "curDataVersion"
	queyrKeyCurSettingVersion = "curSettingVersion"
)

var (
	attackClient                          *http.Client
	ErrATTCKConfDataNotFound              = errors.New("attck conf data not found")
	ErrRuleNotExists                      = errors.New("rule not exists")
	onConflictUpdatedCustomConfigsColumns = []string{
		"rule_category",
	}
)

func init() {
	attackClient = httputil.NewClientWithDefault()
	attackClient.Timeout = 10 * time.Second
}

func LoadAttackRules(ctx context.Context, addr string, curVersion, curDataVersion, curSettingVersion int64) (*model.LatestATTCKRuleInfo, error) {
	url := fmt.Sprintf("%s/api/openapi/ATTCK/latestData?curVersion=%d", addr, curVersion)

	if curDataVersion > 0 {
		url = fmt.Sprintf("%s&%s=%d", url, queryKeyCurDataVersion, curDataVersion)
	}
	if curSettingVersion > 0 {
		url = fmt.Sprintf("%s&%s=%d", url, queyrKeyCurSettingVersion, curSettingVersion)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Create request error. url: %s", url)
		return nil, err
	}

	req.Header.Set(tokenHeader, token)
	resp, err := attackClient.Do(req)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("request error. url: %s", url)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logging.GetLogger().Error().Msgf("Status code is %d. url: %s.", resp.StatusCode, url)
		return nil, fmt.Errorf("status code is: %d", resp.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read all error.")
		return nil, err
	}

	var respData attackResp
	err = json.Unmarshal(bodyBytes, &respData)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("json decode error. data: %s", string(bodyBytes))
		return nil, err
	}
	data := respData.Data.Item

	return data, nil
}

type attackResp struct {
	Data struct {
		Item *model.LatestATTCKRuleInfo `json:"item"`
	} `json:"data"`
}

func LoadATTCKConfDataByVersion1(ctx context.Context, db *gorm.DB, v uint16) (*model.ATTCKRuleData, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	var data model.ATTCKRuleData
	var err = db.WithContext(tctx).Where("version1 = ?", v).Last(&data).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrATTCKConfDataNotFound
		}

		return nil, err
	}

	return &data, nil
}

func LoadATTCKConfData(ctx context.Context, db *gorm.DB) (*model.ATTCKRuleData, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	var data model.ATTCKRuleData
	var err = db.WithContext(tctx).Last(&data).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrATTCKConfDataNotFound
		}

		return nil, err
	}

	return &data, nil
}

func LoadATTCKConfVersion(ctx context.Context, db *gorm.DB, v uint16) (uint32, error) {
	var data model.ATTCKRuleData
	var err = db.WithContext(ctx).Select("id").Where("version1 = ?", v).Order("id desc").Limit(1).Find(&data).Error
	return data.ID, err
}

func SaveATTCKConfData(ctx context.Context, db *gorm.DB, data *model.ATTCKRuleData, deprecatedRuleMasks []string, v uint16) (d *model.ATTCKRuleData, err error) {
	err = db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Create(data).Error; _err != nil {
			return _err
		}

		if len(deprecatedRuleMasks) > 0 {
			if _err := tx.WithContext(ctx).Exec("delete from ivan_platform_attck_rule_masks where name in (?) and version1 = ?", deprecatedRuleMasks, v).Error; _err != nil {
				return _err
			}

			if _err := updateRuleMaskVersion(ctx, tx, v); _err != nil {
				return _err
			}
		}

		return nil
	})

	return data, err
}

func LoadATTCKRuleMaskVersion(ctx context.Context, db *gorm.DB, v uint16) (version uint32, err error) {
	var record model.ATTCKRuleMaskVersion
	err = db.WithContext(ctx).Where("version1 = ?", v).Find(&record).Error
	return record.Version, err
}

func LoadATTCKRuleMasks(ctx context.Context, db *gorm.DB, v uint16) ([]*model.ATTCKRuleMask, error) {
	var records []*model.ATTCKRuleMask
	var err = db.WithContext(ctx).Where("version1 = ?", v).Find(&records).Error
	return records, err
}

func LoadATTCKConfVersions(ctx context.Context, db *gorm.DB, offset, limit int, v string) (int64, []*model.ATTCKConfVersion, error) {

	var records []*model.ATTCKConfVersion
	var dbQuery = db.WithContext(ctx).Model(&model.ATTCKRuleData{}).
		Select("version1, version2, username, created_at")
	if v == "" {
		// dbQuery = dbQuery
	} else if strings.Contains(v, ".") {
		vs := strings.Split(v, ".")
		dbQuery = dbQuery.Where("version1 like ? and version2 like ?", "%"+vs[0], vs[1]+"%")
	} else {
		dbQuery = dbQuery.Where("version1 like ? or version2 like ?", "%"+v+"%", "%"+v+"%")
	}
	dbQuery = dbQuery.Session(&gorm.Session{})

	var err = dbQuery.Order("id desc").Offset(offset).Limit(limit).Find(&records).Error
	if err != nil {
		return 0, nil, err
	}

	var total int64
	err = dbQuery.Count(&total).Error
	return total, records, err
}

func UpdateRuleMask(ctx context.Context, db *gorm.DB, addMasks []*model.ATTCKRuleMask, deletedMasks []string, v uint16) (err error) {
	return db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Exec("delete from ivan_platform_attck_rule_masks where name in (?) and version1 = ?", deletedMasks, v).Error; _err != nil {
			return _err
		}

		if _err := tx.WithContext(ctx).CreateInBatches(addMasks, 100).Error; _err != nil {
			return _err
		}

		return updateRuleMaskVersion(ctx, tx, v)
	})
}

func updateRuleMaskVersion(ctx context.Context, db *gorm.DB, v uint16) (err error) {
	return db.Transaction(func(tx *gorm.DB) error {
		var conf model.ATTCKRuleMaskVersion
		var _err = tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("version1 = ?", v).First(&conf).Error
		if _err != nil {
			if _err == gorm.ErrRecordNotFound {
				return tx.WithContext(ctx).Create(&model.ATTCKRuleMaskVersion{Version1: strconv.Itoa(int(v)), Version: 1}).Error
			}
			return _err
		} else {
			return db.WithContext(ctx).Exec("update ivan_platform_attck_rule_mask_versions set version = version + 1 where version1 = ?", v).Error
		}
	})
}

type CustomConfigsOption struct {
	whereEqCondition   map[string]any
	whereInCondition   map[string]any
	WhereLikeCondition map[string]string
}

func NewCustomConfigsOption() *CustomConfigsOption {
	return &CustomConfigsOption{
		whereEqCondition:   make(map[string]any, 3),
		whereInCondition:   make(map[string]any, 3),
		WhereLikeCondition: make(map[string]string, 2),
	}
}
func (c *CustomConfigsOption) WithEqual(column string, value any) {
	c.whereEqCondition[column] = value
}

func (c *CustomConfigsOption) WithIn(column string, value any) {
	c.whereInCondition[column] = value
}

func (c *CustomConfigsOption) WithLike(column string, value string) {
	c.WhereLikeCondition[column] = value
}

func CountCustomConfigs(ctx context.Context, db *gorm.DB, query *CustomConfigsOption, queryBuilder QueryBuilderFunc) (int, error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	db = db.WithContext(tctx).Model(&model.AttckCustomConfig{})
	if len(query.whereEqCondition) > 0 {
		db = db.Where(query.whereEqCondition)
	}
	if len(query.whereInCondition) > 0 {
		for column, val := range query.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	for col, q := range query.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", col), GetLikeExpr(q))
	}
	if queryBuilder != nil {
		db = queryBuilder(db)
	}
	var cnt int64
	err := db.Count(&cnt).Error
	return int(cnt), err
}

func GetCustomConfigs(ctx context.Context, db *gorm.DB, query *CustomConfigsOption, queryBuilder QueryBuilderFunc, limit, offset int) (configs []*model.AttckCustomConfig, err error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	db = db.WithContext(tctx).Model(&model.AttckCustomConfig{})
	if len(query.whereEqCondition) > 0 {
		db = db.Where(query.whereEqCondition)
	}
	if len(query.whereInCondition) > 0 {
		for column, val := range query.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	for col, q := range query.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s LIKE ?", col), GetLikeExpr(q))
	}
	if queryBuilder != nil {
		db = queryBuilder(db)
	}
	if limit > 0 && offset >= 0 {
		db = db.Offset(offset).Limit(limit)
	}
	err = db.Find(&configs).Error
	return configs, err
}

func CreateCustomConfig(ctx context.Context, db *gorm.DB, data *model.AttckCustomConfig) (uint64, error) {
	if data == nil || db == nil {
		return 0, errors.New("illegal arguments")
	}
	tctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if data.Updater == "" {
		updater := model.GetUsernameFromContext(ctx)
		if updater == "" {
			updater = "system"
		}
		data.Updater = updater
	}
	if data.UpdatedAt == 0 {
		data.UpdatedAt = time.Now().Unix()
	}

	err := db.WithContext(tctx).Transaction(func(tx *gorm.DB) error {
		var d model.AttckCustomConfig
		qerr := tx.WithContext(tctx).Model(&model.AttckCustomConfig{}).Where("cconfig_key = ? AND rule_key = ?", data.CconfigKey, data.RuleKey).Find(&d).Error
		ccolumnsToUpdate := onConflictUpdatedCustomConfigsColumns
		if qerr == gorm.ErrRecordNotFound {
			ccolumnsToUpdate = append(ccolumnsToUpdate, "status")
		} else if qerr != nil {
			return qerr
		}
		return tx.WithContext(tctx).Model(&model.AttckCustomConfig{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "rule_key"}, {Name: "cconfig_key"}},
			DoUpdates: clause.AssignmentColumns(ccolumnsToUpdate),
		}).Create(data).Error
	})

	return data.ID, err
}

type UpdateFunc func(ctx context.Context, oldValue string) (newValue string, err error)

func ModifyCustomConfigValues(ctx context.Context, db *gorm.DB, ruleKey, cconfigKey string, ufunc UpdateFunc) error {
	if ufunc == nil || db == nil {
		return errors.New("illegal arguments")
	}

	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err := db.WithContext(tctx).Transaction(func(tx *gorm.DB) error {
		var config model.AttckCustomConfig
		qerr := tx.WithContext(tctx).Model(&model.AttckCustomConfig{}).Select("id", "cconfig_value").Where("rule_key = ? AND cconfig_key = ?", ruleKey, cconfigKey).Find(&config).Error
		if qerr == gorm.ErrRecordNotFound {
			return nil
		} else if qerr != nil {
			return qerr
		}
		newValue, uerr := ufunc(tctx, config.CconfigValue)
		if uerr != nil {
			return uerr
		}
		return tx.WithContext(tctx).Model(&model.AttckCustomConfig{}).Where("rule_key = ? AND cconfig_key = ?", ruleKey, cconfigKey).Updates(map[string]any{
			"cconfig_value": newValue,
			"status":        model.StatusPending,
			"updated_at":    time.Now().Unix(),
			"updater":       model.GetUsernameFromContext(tctx),
		}).Error
	})
	return err
}

func UpdateCustomConfig(ctx context.Context, db *gorm.DB, query *CustomConfigsOption, data map[string]any) error {
	if data == nil || len(data) == 0 || db == nil {
		return errors.New("illegal arguments")
	}
	tctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if v, exist := data["updated_at"]; !exist || v == nil {
		data["updated_at"] = time.Now().Unix()
	}
	if v, exist := data["updater"]; !exist || v == nil {
		updater := model.GetUsernameFromContext(ctx)
		data["updater"] = updater
	}

	db = db.WithContext(tctx).Model(&model.AttckCustomConfig{}).Select("rule_category", "cconfig_name", "cconfig_value", "cconfig_effect", "updated_at", "updater", "status")
	if len(query.whereEqCondition) > 0 {
		db = db.Where(query.whereEqCondition)
	}
	if len(query.whereInCondition) > 0 {
		for column, val := range query.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	for col, q := range query.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("LOWER(%s) LIKE LOWER(?)", col), GetLikeExpr(q))
	}
	return db.Updates(data).Error
}

func SetCustomConfigStatus(ctx context.Context, db *gorm.DB, id uint64, status model.CconfigStatus) error {
	if db == nil {
		return errors.New("illegal arguments")
	}

	tctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	data := make(map[string]interface{}, 3)
	data["updated_at"] = time.Now().Unix()
	updater := model.GetUsernameFromContext(ctx)
	data["updater"] = updater
	data["status"] = status
	if status == model.StatusDeleted {
		data["cconfig_value"] = ""
	}
	return db.WithContext(tctx).Model(&model.AttckCustomConfig{}).Where("id = ?", id).Updates(data).Error
}

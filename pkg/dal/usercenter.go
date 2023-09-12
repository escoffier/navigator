package dal

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"math/rand"
	"time"
	"unsafe"

	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/id"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits

	ModuleUserCenter = 1
)

func RandStringBytesMaskImprSrcUnsafe(n int) string {
	var src = rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

func UpdateUserPwd(ctx context.Context, rdb *gorm.DB, userName string, pwd string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, u, err := SelectUser(pgCtx, rdb, userName)
	if err != nil {
		return err
	}

	err = rdb.WithContext(pgCtx).Model(&model.User{}).
		Where("username = ? ", userName).
		Updates(map[string]interface{}{"pwd": fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt))), "must_change_pwd": false, "last_change_pwd_at": time.Now().UnixMilli()}).
		Error

	if err != nil {
		return errors.New("UpdateUserPwd() -> mongodb.Collection().UpdateOne() err : " + err.Error())
	}
	return nil
}

func SelectUserAll(ctx context.Context, rdb *gorm.DB, keyword string, roles []string, statuses []int, modules []string, limit, offset int) (int64, []model.User, error) {
	var user []model.User
	var count int64

	db := rdb.WithContext(ctx).Where("rule <> ?", model.RoleTypeSuperAdmin)
	if keyword != "" {
		db = db.Where("account LIKE ?", "%"+keyword+"%")
	}
	if len(roles) != 0 {
		db = db.Where("rule IN ?", roles)
	}
	if len(statuses) != 0 {
		db = db.Where("status IN ?", statuses)
	}
	if len(modules) != 0 {
		for i := range modules {
			db = db.Where("module_id like ?", `%"`+modules[i]+`"%`)
		}
	}

	var err = db.Model(&model.User{}).Count(&count).Error
	if err != nil {
		return 0, nil, err
	}

	err = db.Limit(limit).Offset(offset).Order("id DESC").Find(&user).Error
	if err != nil {
		return count, user, err
	}

	return count, user, nil
}

func GetModuleGroup(ctx context.Context, db *gorm.DB, moduleID string) ([]model.ModuleGroup, error) {
	if moduleID == "" {
		return nil, nil
	}
	var moduleSLID []string
	var err = json.Unmarshal([]byte(moduleID), &moduleSLID)
	if err != nil {
		return nil, err
	}
	var m []model.ModuleGroup
	err = db.WithContext(ctx).Where("id in  (?) and id not in (?)", moduleSLID, []int{ModuleUserCenter}).Find(&m).Error
	return m, err
}

func GetAccessUrl(db *gorm.DB, moduleID string) ([]string, error) {
	var (
		m      []model.ModuleGroup
		ids    []int
		url    []model.Url
		strURL []string
	)

	var moduleSLID []string
	var err error
	if moduleID != "" {
		err = json.Unmarshal([]byte(moduleID), &moduleSLID)
		if err != nil {
			return nil, err
		}
	}

	pgCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err = db.WithContext(pgCtx).Where("Id in (?)", moduleSLID).Find(&m).Error
	if err != nil {
		return nil, err
	}

	for _, v := range m {
		ids = append(ids, v.Id)
	}
	ids = append(ids, ModuleUserCenter)
	err = db.Where("url_id in (?)", ids).Find(&url).Error
	if err != nil {
		return nil, err
	}
	for _, v := range url {
		strURL = append(strURL, v.UrlName)
	}
	return strURL, nil
}

func SetAccountStatus(ctx context.Context, rdb *gorm.DB, account string, status int) error {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	var innerErr error
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(pgCtx, 300*time.Millisecond)
		defer oneCancel()
		innerErr = rdb.WithContext(oneCtx).Model(&model.User{}).Where("account = ?", account).
			Update("status", status).Error
		if innerErr == gorm.ErrRecordNotFound {
			return nil
		}
		return innerErr
	})

	if err == nil {
		if innerErr != nil {
			return innerErr
		}
		return nil
	}
	return err
}

func GetAdminModuleGroup(ctx context.Context, db *gorm.DB) ([]model.ModuleGroup, error) {
	var m []model.ModuleGroup

	tCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := db.WithContext(tCtx).Where("id not in  (?)", []int{ModuleUserCenter}).Find(&m).Error
	return m, err
}

func GetAllModules(ctx context.Context, db *gorm.DB) ([]*model.ModuleGroup, error) {
	var m []*model.ModuleGroup
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var err = db.WithContext(pgCtx).Find(&m).Error
	return m, err
}

func GetUserLiteWithCache(ctx context.Context, rdb *gorm.DB, redisClient *redis.Client, username string) (*model.UserLite, error) {
	queryUser := model.UserLite{}

	redisCtx, cancel := context.WithTimeout(ctx, time.Millisecond*500)
	defer cancel()

	key := fmt.Sprintf("u:%s", username)
	rawJson, err := redisClient.Get(redisCtx, key).Bytes()
	if err == nil {
		if err = json.Unmarshal(rawJson, &queryUser); err != nil {
			logging.Get().Error().Err(err).Msg("")
		}
	}

	if err != nil {
		logging.Get().Warn().Err(err).Msg("")

		u := model.User{}
		err = rdb.WithContext(ctx).Select("username", "account").
			Where("username = ?", username).First(&u).Error
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			return nil, err
		}

		queryUser.Username = u.UserName
		queryUser.Account = u.Account
		if err == redis.Nil {
			b, err := json.Marshal(queryUser)
			if err != nil {
				logging.Get().Error().Err(err).Msg("")
			}

			if err = redisClient.Set(redisCtx, key, b, time.Minute*10).Err(); err != nil {
				logging.Get().Error().Err(err).Msg("save to cache failed")
			}
		}
	}

	return &queryUser, nil
}

func SelectUser(ctx context.Context, rdb *gorm.DB, userName string) (bool, *model.User, error) {
	queryUser := model.User{}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err := rdb.WithContext(pgCtx).Model(&queryUser).Where("username = ?", userName).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, &queryUser, nil
}

func SelectUserByAccount(ctx context.Context, rdb *gorm.DB, account string) (bool, *model.User, error) {
	queryUser := model.User{}

	err := rdb.WithContext(ctx).Model(&queryUser).Where("account = ?", account).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, &queryUser, nil
}

func InsertInactiveUser(ctx context.Context, rdb *gorm.DB, account string, role model.RoleType, moduleID []string, mustChangePwd bool, creator string) (*model.User, error) {
	data, err := json.Marshal(moduleID)
	if err != nil {
		return nil, err
	}
	user := model.User{
		UserName:      id.Str(),
		Account:       account,
		Nickname:      account,
		Salt:          RandStringBytesMaskImprSrcUnsafe(8),
		Role:          role,
		ModuleID:      string(data),
		CreatedAt:     time.Now().Unix(),
		Creator:       creator,
		Status:        model.UserStatusInactive,
		MustChangePwd: mustChangePwd,
	}

	err = rdb.WithContext(ctx).Create(&user).Error
	return &user, err
}

func UpdateUser(ctx context.Context, rdb *gorm.DB, userName, account string, moduleID []string) (err error) {
	data, _ := json.Marshal(moduleID)

	return rdb.WithContext(ctx).Model(&model.User{}).
		Where("username = ? ", userName).
		UpdateColumns(map[string]interface{}{
			"account":   account,
			"module_id": data,
		}).Error
}

func InsertEmail(ctx context.Context, rdb *gorm.DB, username, hashcode string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	// TODO insert on duplicate key update
	err := rdb.WithContext(pgCtx).Delete(model.Email{}, "username = ?", username).Error
	if err != nil {
		logging.Get().Err(err).Msgf("Insert email to delete error: username: %s", username)
	}
	email := model.Email{HashCode: hashcode, UserName: username, CreatedAt: time.Now().Unix()}

	err = rdb.WithContext(pgCtx).Create(&email).Error
	return err
}

func GetSaltedPwd(pwd, salt string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(pwd+salt)))
}

func GetUserByAccountPwd(ctx context.Context, db *gorm.DB, account, pwd string) (bool, *model.User, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	queryUser := model.User{}
	err := db.WithContext(pgCtx).Where("account = ?", account).First(&queryUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil, nil
		}
		return false, nil, err
	}
	if GetSaltedPwd(pwd, queryUser.Salt) == queryUser.Pwd {
		return true, &queryUser, nil
	} else {
		return false, &queryUser, nil
	}
}

func UpdateUserPasswordToNow(ctx context.Context, db *gorm.DB) error {
	// must_change_pwd <> 1 and status = 1 and platform = ''
	return db.WithContext(ctx).Model(&model.User{}).Where("must_change_pwd <> 1 AND status = ? AND platform = ''", model.UserStatusNormal).
		UpdateColumns(map[string]interface{}{
			"last_change_pwd_at": time.Now().UnixMilli(),
		}).Error
}

func CheckHashCode(ctx context.Context, db *gorm.DB, hashCode string) (string, bool) {
	queryEmail := model.Email{}

	tCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := db.WithContext(tCtx).Where("hash_code = ?", hashCode).First(&queryEmail).Error
	if err != nil {
		logging.Get().Err(err).Msgf("get email hashcode error:%+v", err)
		return "", false
	}
	return queryEmail.UserName, true
}

func ActiveUser(ctx context.Context, db *gorm.DB, userName, pwd string, mustChangePwd bool) (*model.User, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	exists, u, err := SelectUser(pgCtx, db, userName)
	if err != nil {
		return u, err
	}

	if !exists {
		return u, fmt.Errorf("user not exists")
	}

	hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt)))
	authToken := util.GenerateUUIDHex()

	err = db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(pgCtx).Model(u).
			Where("username = ? ", userName).
			Updates(map[string]interface{}{"status": model.UserStatusNormal, "pwd": hashPwd, "must_change_pwd": mustChangePwd, "last_change_pwd_at": time.Now().UnixMilli()}).
			Error; _err != nil {
			return _err
		}

		if _err := tx.WithContext(pgCtx).Where("username = ? ", userName).Delete(&model.Email{}).Error; _err != nil {
			return _err
		}

		return SaveAuthToken(ctx, tx, userName, authToken)
	})

	return u, err
}

func GetModules(ctx context.Context, db *gorm.DB, moduleIDs []int) ([]*model.ModuleGroup, error) {
	var result []*model.ModuleGroup
	var err = db.WithContext(ctx).Where("id in (?)", moduleIDs).Find(&result).Error
	return result, err
}

func UpdateUserStatus(ctx context.Context, db *gorm.DB, username string, status int) error {
	return db.WithContext(ctx).Model(&model.User{}).Where("username = ?", username).
		UpdateColumns(map[string]interface{}{
			"status": status,
		}).Error
}

func UpdateUserToken(ctx context.Context, db *gorm.DB, username, tokenStr string, expireAt int64) error {
	return db.WithContext(ctx).Model(&model.User{}).Where("username = ?", username).
		UpdateColumns(map[string]interface{}{
			"token":           tokenStr,
			"token_expire_at": expireAt,
		}).Error
}

func UpdateUserTokenExpireAt(ctx context.Context, db *gorm.DB, username string, expireAt int64) error {
	return db.WithContext(ctx).Model(&model.User{}).
		Where("username = ?", username).
		UpdateColumn("token_expire_at", expireAt).Error
}

func UpdateUserLoginKey(ctx context.Context, db *gorm.DB, account, key string, expireAt int64) error {
	return db.WithContext(ctx).Model(&model.User{}).Where("account = ?", account).
		UpdateColumns(map[string]interface{}{
			"login_secret_key":           key,
			"login_secret_key_expire_at": expireAt,
		}).Error

}

func HasSuperadminUser(ctx context.Context, db *gorm.DB) (bool, error) {
	err := db.WithContext(ctx).Where("rule = ?", model.RoleTypeSuperAdmin).First(&model.User{}).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return false, err
	}

	return err == nil, nil
}

func CreateSuperAdmin(ctx context.Context, db *gorm.DB, account, pwd string) error {
	err := db.WithContext(ctx).Where("username = ? OR account = ?", model.SuperAdminUsername, account).First(&model.User{}).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return err
		}
	} else {
		return fmt.Errorf("super admin is exists")
	}

	salt := RandStringBytesMaskImprSrcUnsafe(8)
	hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(pwd+salt)))
	user := model.User{
		UserName:  model.SuperAdminUsername,
		Account:   account,
		Nickname:  account,
		Status:    model.UserStatusNormal,
		CreatedAt: time.Now().Unix(),
		Creator:   "system",
		ModuleID:  "[]",
		Role:      model.RoleTypeSuperAdmin,
		Salt:      salt,
		Pwd:       hashPwd,
	}
	authToken := util.GenerateUUIDHex()

	err = db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Create(&user).Error; _err != nil {
			return _err
		}

		return SaveAuthToken(ctx, tx, user.UserName, authToken)
	})
	if err != nil {
		return err
	}

	return err
}

// mfa
// 消除mfa密钥绑定信息
func DeleteUserMfaSecret(ctx context.Context, db *gorm.DB) error {
	return db.WithContext(ctx).Model(&model.User{}).Where("1 = 1").
		Updates(map[string]interface{}{
			"mfa_secret": "",
			"MfaStatus":  false,
		}).Error
}

// 存储密钥值信息
func UpdateUserMfaSecret(ctx context.Context, db *gorm.DB, secret, username string) error {
	return db.WithContext(ctx).Model(&model.User{}).Where("username = ?", username).
		Updates(map[string]interface{}{
			"mfa_secret": secret,
			"MfaStatus":  false,
		}).Error
}

// 更新mfa密钥的绑定状态
func UpdateUserMfaStatus(ctx context.Context, db *gorm.DB, mfaStatus bool, username string) error {
	return db.WithContext(ctx).Model(&model.User{}).Where("username = ?", username).
		Updates(map[string]interface{}{
			"MfaStatus": mfaStatus,
		}).Error
}

// 更新二步登录验证密钥  --添加
func UpdateLoginTwoFactorSecret(ctx context.Context, db *gorm.DB, account, TwoFactorSecret string, expireAt int64) error {
	return db.WithContext(ctx).Model(&model.User{}).Where("account = ?", account).
		UpdateColumns(map[string]interface{}{
			"two_factor_key":           TwoFactorSecret,
			"two_factor_key_expire_at": expireAt,
		}).Error
}

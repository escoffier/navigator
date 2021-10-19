package dal

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"unsafe"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	MongoUserCollectionName = "rbac_user"
	letterIdxBits           = 6                    // 6 bits to represent a letter index
	letterIdxMask           = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax            = 63 / letterIdxBits   // # of letter indices fitting in 63 bits

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

func UpdateUserPwd(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName string, pwd string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, u, err := SelectUser(pgCtx, postgresDB.Get(), userName)
	if err != nil {
		return err
	}

	err = postgresDB.Get().WithContext(pgCtx).Model(&model.User{}).Where("username = ? ", userName).Update("pwd", fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt)))).Error

	if err != nil {
		return errors.New("UpdateUserPwd() -> mongodb.Collection().UpdateOne() err : " + err.Error())
	}
	return nil
}

func SelectUserAll(ctx context.Context, postgresDB *rdbtools.GormWrapper, limit, offset int64) (int64, []model.User, error) {
	var user []model.User
	var count int64

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var err = postgresDB.Get().WithContext(pgCtx).Where("username != ?", model.UserSuperAdmin).Model(&model.User{}).Count(&count).Error
	if err != nil {
		return 0, nil, err
	}

	p := postgresDB.Get().WithContext(pgCtx).Where("username != ?", model.UserSuperAdmin).Limit(int(limit)).Offset(int(offset)).Order("id")
	err = p.Where("username != ?", model.UserSuperAdmin).Find(&user).Error
	if err != nil {
		return count, user, err
	}

	for i := range user {
		groups, err := GetModuleGroup(pgCtx, postgresDB, user[i].ModuleID)
		if err == nil {
			user[i].ModuleGroup = append(user[i].ModuleGroup, groups...)
		}
	}

	return count, user, nil
}

func GetModuleGroup(ctx context.Context, db *rdbtools.GormWrapper, moduleID string) ([]model.ModuleGroup, error) {
	if moduleID == "" {
		return nil, nil
	}
	var moduleSLID []string
	var err = json.Unmarshal([]byte(moduleID), &moduleSLID)
	if err != nil {
		return nil, err
	}
	var m []model.ModuleGroup
	err = db.Get().WithContext(ctx).Where("id in  (?) and id not in (?)", moduleSLID, []int{ModuleUserCenter}).Find(&m).Error
	return m, err
}

func GetAccessUrl(db *rdbtools.GormWrapper, moduleID string) ([]string, error) {
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
	err = db.Get().WithContext(pgCtx).Where("Id in (?)", moduleSLID).Find(&m).Error
	if err != nil {
		return nil, err
	}

	for _, v := range m {
		ids = append(ids, v.Id)
	}
	ids = append(ids, ModuleUserCenter)
	err = db.Get().Where("url_id in (?)", ids).Find(&url).Error
	if err != nil {
		return nil, err
	}
	for _, v := range url {
		strURL = append(strURL, v.UrlName)
	}
	return strURL, nil
}

func SetAccountBanStatus(ctx context.Context, rdb *rdbtools.GormWrapper, userName string, banStatus bool) error {
	bStatus := 0
	if banStatus {
		bStatus = 1
	}

	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	var innerErr error
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, oneCancel := context.WithTimeout(pgCtx, 300*time.Millisecond)
		defer oneCancel()
		innerErr = rdb.Get().WithContext(oneCtx).Model(&model.User{}).Where("username = ?", userName).Update("ban_status", bStatus).Error
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

func GetAdminModuleGroup(ctx context.Context, db *rdbtools.GormWrapper) []model.ModuleGroup {

	var m []model.ModuleGroup

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	db.Get().WithContext(pgCtx).Where("id not in  (?)", []int{ModuleUserCenter}).Find(&m)
	logging.GetLogger().Info().Msgf("moduleGroup:%+v", m)
	return m
}

func SelectUser(ctx context.Context, postgresDB *gorm.DB, userName string) (bool, *model.User, error) {

	queryUser := model.User{}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := postgresDB.WithContext(pgCtx).Model(&queryUser).Where("username = ?", userName).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, &queryUser, nil
}

func InsertUser(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName, role string, moduleID []string) (err error) {
	data, err := json.Marshal(moduleID)
	if err != nil {
		return err
	}
	user := model.User{UserName: userName, Checked: false, CreateAt: time.Now().Unix(), Rule: role, ModuleID: string(data), Salt: RandStringBytesMaskImprSrcUnsafe(8)}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return postgresDB.Get().WithContext(pgCtx).Clauses(clause.OnConflict{DoNothing: true}).Create(&user).Error
}

func InsertUserV2(ctx context.Context, postgresDB *gorm.DB, userName, role string, moduleID []string) (err error) {
	data, err := json.Marshal(moduleID)
	if err != nil {
		return err
	}
	user := model.User{UserName: userName, Checked: false, CreateAt: time.Now().Unix(), Rule: role, ModuleID: string(data), Salt: RandStringBytesMaskImprSrcUnsafe(8)}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return postgresDB.WithContext(pgCtx).Create(&user).Error
}

func UpdateUser(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName, role string, moduleID []string) (err error) {
	data, _ := json.Marshal(moduleID)
	user := model.User{Rule: role, ModuleID: string(data)}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return postgresDB.Get().WithContext(pgCtx).Model(&model.User{}).Where("username = ? ", userName).Updates(user).Error
}

func InsertEmail(ctx context.Context, postgresDB *gorm.DB, username, hashcode string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	// TODO insert on duplicate key update
	err := postgresDB.WithContext(pgCtx).Delete(model.Email{}, "username = ?", username).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Insert email to delete error: username: %s", username)
	}
	email := model.Email{HashCode: hashcode, UserName: username, CreateAt: time.Now().Unix()}

	err = postgresDB.WithContext(pgCtx).Create(&email).Error
	return err
}

func GetSaltedPwd(pwd, salt string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(pwd+salt)))
}
func LoginCheckByPostgres(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName, pwd string) (bool, *model.User, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	queryUser := model.User{}
	err := postgresDB.Get().WithContext(pgCtx).Where("username = ?", userName).First(&queryUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil, nil
		}
		return false, nil, err
	}
	if GetSaltedPwd(pwd, queryUser.Salt) == queryUser.Pwd {
		return true, &queryUser, nil
	} else {
		return false, nil, nil
	}
}

func CheckHashCode(ctx context.Context, postgresDB *rdbtools.GormWrapper, hashCode string) (string, bool) {
	queryEmail := model.Email{}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := postgresDB.Get().WithContext(pgCtx).Where("hash_code = ?", hashCode).First(&queryEmail).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get email hashcode error:%+v", err)
		return "", false
	}
	return queryEmail.UserName, true
}

func ActiveUser(ctx context.Context, postgresDB *gorm.DB, userName, pwd string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	exists, u, err := SelectUser(pgCtx, postgresDB, userName)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("user not exists")
	}

	//if u.Checked {
	//	return fmt.Errorf("already actived")
	//}

	hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt)))
	authToken := util.GenerateUUIDHex()

	return postgresDB.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(pgCtx).Model(model.User{}).Where("username = ? ", userName).Updates(model.User{Checked: true, Pwd: hashPwd}).Error; _err != nil {
			return _err
		}

		if _err := tx.WithContext(pgCtx).Where("username = ? ", userName).Delete(&model.Email{}).Error; _err != nil {
			return _err
		}

		return SaveAuthToken(ctx, tx, userName, authToken)
	})
}

func GetModules(ctx context.Context, db *gorm.DB, moduleIDs []int) ([]*model.ModuleGroup, error) {
	var result []*model.ModuleGroup
	var err = db.WithContext(ctx).Where("id in (?)", moduleIDs).Find(&result).Error
	return result, err
}

func GetUserByMongo(ctx context.Context, mongodb *mongo.Database) (u []model.MongoUser, err error) {

	opt := options.Find().SetMaxTime(time.Second * 2)

	cur, err := mongodb.Collection(MongoUserCollectionName).Find(ctx, bson.M{}, opt)
	if err != nil {
		apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find document: %w", err))
		return
	}

	mongoUserSlice := make([]model.MongoUser, 0)
	for cur.Next(ctx) {
		var mu model.MongoUser
		err := cur.Decode(&mu)
		if err != nil {
			return nil, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't decode document: %w", err))
		}
		mongoUserSlice = append(mongoUserSlice, mu)
	}
	return mongoUserSlice, nil
}

func IsPostgresDuplicateError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(strings.ToLower(err.Error()), "duplicate")
}

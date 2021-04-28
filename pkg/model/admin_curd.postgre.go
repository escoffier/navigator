package model

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/gorm"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits           = 6                    // 6 bits to represent a letter index
	letterIdxMask           = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax            = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	MongoUserCollectionName = "rbac_user"
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
	_, u, err := SelectUser(pgCtx, postgresDB, userName)
	if err != nil {
		return err
	}

	err = postgresDB.Get().WithContext(pgCtx).Model(&User{}).Where("username = ? ", userName).Update("pwd", fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt)))).Error

	if err != nil {
		return errors.New("UpdateUserPwd() -> mongodb.Collection().UpdateOne() err : " + err.Error())
	}
	return nil
}

func SelectUserAll(ctx context.Context, postgresDB *rdbtools.GormWrapper, limit, offset int64) (int64, []User, error) {
	user := []User{}
	var count int64

	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	postgresDB.Get().WithContext(pgCtx).Where("username != ?", SUPER_ADMIN).Model(&User{}).Count(&count)

	p := postgresDB.Get().WithContext(pgCtx).Where("username != ?", SUPER_ADMIN).Limit(int(limit)).Offset(int(offset)).Order("id")
	err := p.Where("username != ?", SUPER_ADMIN).Find(&user).Error
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

func GetModuleGroup(ctx context.Context, db *rdbtools.GormWrapper, moduleID string) ([]ModuleGroup, error) {

	var moduleSLID []string
	json.Unmarshal([]byte(moduleID), &moduleSLID)
	var m []ModuleGroup
	err := db.Get().WithContext(ctx).Where("id in  (?) and id not in (?)", moduleSLID, []int{1}).Find(&m).Error
	return m, err
}

func GetAccessUrl(db *rdbtools.GormWrapper, moduleID string) ([]string, error) {
	var (
		m      []ModuleGroup
		ids    []int
		url    []Url
		strURL []string
	)
	var moduleSLID []string
	json.Unmarshal([]byte(moduleID), &moduleSLID)

	pgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := db.Get().WithContext(pgCtx).Where("Id in  (?)", moduleSLID).Find(&m).Error
	if err != nil {
		return strURL, err
	}

	for _, v := range m {
		ids = append(ids, v.Id)
	}
	ids = append(ids, 1)
	err = db.Get().Where("url_id in (?)", ids).Find(&url).Error
	if err != nil {
		return strURL, err
	}
	for _, v := range url {
		strURL = append(strURL, v.UrlName)
	}
	return strURL, nil
}

func GetAdminModuleGroup(ctx context.Context, db *rdbtools.GormWrapper) []ModuleGroup {

	var m []ModuleGroup

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	db.Get().WithContext(pgCtx).Where("id not in  (?)", []int{1}).Find(&m)
	logging.GetLogger().Info().Msgf("moduleGroup:%+v", m)
	return m
}

func SelectUser(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName string) (bool, *User, error) {

	queryUser := User{}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := postgresDB.Get().WithContext(pgCtx).Where("username = ?", userName).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, &queryUser, nil
}

func InsertUser(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName, role string, moduleID []string) (err error) {
	data, _ := json.Marshal(moduleID)
	user := User{UserName: userName, Checked: false, CreateAt: time.Now().Unix(), Rule: role, ModuleID: string(data), Salt: RandStringBytesMaskImprSrcUnsafe(8)}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = postgresDB.Get().WithContext(pgCtx).Create(&user).Error
	if err != nil {
		return err
	}
	return
}

func UpdateUser(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName, role string, moduleID []string) (err error) {
	data, _ := json.Marshal(moduleID)
	user := User{Rule: role, ModuleID: string(data)}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = postgresDB.Get().WithContext(pgCtx).Model(&User{}).Where("username = ? ", userName).Updates(user).Error
	if err != nil {
		return err
	}
	return
}

func InsertEmail(ctx context.Context, postgresDB *rdbtools.GormWrapper, username, hashcode string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	err := postgresDB.Get().WithContext(pgCtx).Delete(Email{}, "username = ?", username).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Insert email to delete error: username: %s", username)
	}
	email := Email{HashCode: hashcode, UserName: username, CreateAt: time.Now().Unix()}

	err = postgresDB.Get().WithContext(pgCtx).Create(&email).Error
	return err
}

func DelSuperUser(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := postgresDB.Get().WithContext(pgCtx).Model(User{}).Where("username = ? ", userName).Updates(User{Pwd: ""}).Error
	if err != nil {
		return err
	}
	return nil
}

func LoginCheckByPostgres(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName, pwd string) (bool, *User, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	queryUser := User{}
	err := postgresDB.Get().WithContext(pgCtx).Where("username = ?", userName).First(&queryUser).Error
	if err != nil {
		return false, nil, err
	}
	if fmt.Sprintf("%x", md5.Sum([]byte(pwd+queryUser.Salt))) == queryUser.Pwd {
		return true, &queryUser, nil
	} else {
		return false, nil, nil
	}
}

func CheckHashCode(ctx context.Context, postgresDB *rdbtools.GormWrapper, hashCode string) (string, bool) {
	queryEmail := Email{}

	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := postgresDB.Get().WithContext(pgCtx).Where("hash_code = ?", hashCode).First(&queryEmail).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get email hashcode error:%+v", err)
		return "", false
	}
	return queryEmail.UserName, true
}

func ActiveUser(ctx context.Context, postgresDB *rdbtools.GormWrapper, userName, pwd string) error {
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, u, err := SelectUser(pgCtx, postgresDB, userName)
	if err != nil {
		return err
	}
	hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt)))
	err = postgresDB.Get().WithContext(pgCtx).Model(User{}).Where("username = ? ", userName).Updates(User{Checked: true, Pwd: hashPwd}).Error

	if err != nil {
		return err
	}

	err = postgresDB.Get().WithContext(pgCtx).Where("username = ? ", userName).Delete(&Email{}).Error

	if err != nil {
		return err
	}
	return nil
}

func GetUserByMongo(ctx context.Context, mongodb *mongo.Database) (u []MongoUser, err error) {

	opt := options.Find().SetMaxTime(time.Second * 2)

	cur, err := mongodb.Collection(MongoUserCollectionName).Find(ctx, bson.M{}, opt)
	if err != nil {
		apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find document: %w", err))
		return
	}

	mongoUserSlice := make([]MongoUser, 0)
	for cur.Next(ctx) {
		var mu MongoUser
		err := cur.Decode(&mu)
		if err != nil {
			return nil, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't decode document: %w", err))
		}
		mongoUserSlice = append(mongoUserSlice, mu)
	}
	return mongoUserSlice, nil
}

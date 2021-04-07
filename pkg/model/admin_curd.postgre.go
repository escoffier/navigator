package model

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jinzhu/gorm"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"math/rand"
	"unsafe"

	"time"
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

func UpdateUserPwd(postgresDB *gorm.DB, userName string, pwd string) error {

	//

	_, u, err := SelectUser(postgresDB, userName)
	if err != nil {
		return err
	}

	err = postgresDB.Model(&User{}).Where("username = ? ", userName).Update("pwd", fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt)))).Error

	if err != nil {
		return errors.New("UpdateUserPwd() -> mongodb.Collection().UpdateOne() err : " + err.Error())
	}
	return nil
}

func SelectUserAll(postgresDB *gorm.DB, limit, offset int64) (int64, []User, error) {

	user := []User{}
	var count int64
	postgresDB.Where("username != ?", SUPER_ADMIN).Model(&User{}).Count(&count)

	p := postgresDB.Where("username != ?", SUPER_ADMIN).Limit(limit).Offset(offset).Order("id")
	err := p.Where("username != ?", SUPER_ADMIN).Find(&user).Error
	if err != nil {
		return count, user, err
	}

	for i := range user {
		user[i].ModuleGroup = append(user[i].ModuleGroup, GetModuleGroup(postgresDB, user[i].ModuleID)...)
	}

	return count, user, nil
}

func GetModuleGroup(db *gorm.DB, moduleID string) []ModuleGroup {

	var moduleSLID []string
	json.Unmarshal([]byte(moduleID), &moduleSLID)
	var m []ModuleGroup
	db.Where("id in  (?) and id not in (?)", moduleSLID, []int{1}).Find(&m)
	return m
}

func GetAccessUrl(db *gorm.DB, moduleID string) ([]string, error) {
	var (
		m      []ModuleGroup
		ids    []int
		url    []Url
		strURL []string
	)
	var moduleSLID []string
	json.Unmarshal([]byte(moduleID), &moduleSLID)

	err := db.Where("Id in  (?)", moduleSLID).Find(&m).Error
	if err != nil {
		return strURL, err
	}

	for _, v := range m {
		ids = append(ids, v.Id)
	}
	ids = append(ids, 1)
	err = db.Where("url_id in (?)", ids).Find(&url).Error
	if err != nil {
		return strURL, err
	}
	for _, v := range url {
		strURL = append(strURL, v.UrlName)
	}
	return strURL, nil
}

func GetAdminModuleGroup(db *gorm.DB) []ModuleGroup {

	var m []ModuleGroup
	db.Where("id not in  (?)", []int{1}).Find(&m)
	logging.GetLogger().Info().Msgf("moduleGroup:%+v", m)
	return m
}

func SelectUser(postgresDB *gorm.DB, userName string) (bool, *User, error) {

	queryUser := User{}

	err := postgresDB.Where("username = ?", userName).First(&queryUser).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, &queryUser, nil
}

func InsertUser(postgresDB *gorm.DB, userName, role string, moduleID []string) (err error) {
	data, _ := json.Marshal(moduleID)
	user := User{UserName: userName, Checked: false, CreateAt: time.Now().Unix(), Rule: role, ModuleID: string(data), Salt: RandStringBytesMaskImprSrcUnsafe(8)}
	err = postgresDB.Create(&user).Error
	if err != nil {
		return err
	}
	return
}

func UpdateUser(postgresDB *gorm.DB, userName, role string, moduleID []string) (err error) {
	data, _ := json.Marshal(moduleID)
	user := User{Rule: role, ModuleID: string(data)}
	err = postgresDB.Model(&User{}).Where("username = ? ", userName).Update(user).Error
	if err != nil {
		return err
	}
	return
}

func InsertEmail(postgresDB *gorm.DB, username, hashcode string) error {
	postgresDB.Delete(Email{}, "username = ?", username)
	email := Email{HashCode: hashcode, UserName: username, CreateAt: time.Now().Unix()}
	err := postgresDB.Create(&email).Error
	return err
}

func DelSuperUser(postgresDB *gorm.DB, userName string) error {
	err := postgresDB.Model(User{}).Where("username = ? ", userName).Update(User{Pwd: ""}).Error
	if err != nil {
		return err
	}
	return nil
}

func LoginCheckByPostgres(postgresDB *gorm.DB, userName, pwd string) (bool, *User, error) {
	queryUser := User{}
	err := postgresDB.Where("username = ?", userName).First(&queryUser).Error
	if err != nil {
		return false, nil, err
	}
	if fmt.Sprintf("%x", md5.Sum([]byte(pwd+queryUser.Salt))) == queryUser.Pwd {
		return true, &queryUser, nil
	} else {
		return false, nil, nil
	}
}

func CheckHashCode(postgresDB *gorm.DB, hashCode string) (string, bool) {
	queryEmail := Email{}
	err := postgresDB.Where("hash_code = ?", hashCode).First(&queryEmail).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get email hashcode error:%+v", err)
		return "", false
	}
	return queryEmail.UserName, true
}

func ActiveUser(postgresDB *gorm.DB, userName, pwd string) error {

	_, u, err := SelectUser(postgresDB, userName)
	if err != nil {
		return err
	}
	hashPwd := fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt)))
	err = postgresDB.Model(User{}).Where("username = ? ", userName).Update(User{Checked: true, Pwd: hashPwd}).Error

	if err != nil {
		return err
	}

	err = postgresDB.Where("username = ? ", userName).Delete(&Email{}).Error

	if err != nil {
		return err
	}
	return nil
}

func GetUserByMongo(ctx context.Context, mongodb *mongo.Database) (u []MongoUser, err error) {

	opt := options.Find()
	opt.SetMaxTime(time.Second * 2)

	cur, err := mongodb.Collection(MongoUserCollectionName).Find(ctx, bson.M{}, opt)
	if err != nil {
		apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find document: %w", err))
		return nil, err
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

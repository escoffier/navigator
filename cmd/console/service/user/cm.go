package user

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/apache/pulsar-client-go/pulsar"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/idp"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	instance *CMUserService
	once     sync.Once
	cmClient *http.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	cmALGO    = "HS256"
	cmAuthKey = "PWGKz4CPdOGVBLd7CgHzyPrRhlSikiTG"
)

const (
	CMAPIHostEnvKey   = "CM_API_HOST"
	CMAPIKeyEnvKey    = "CM_API_KEY"
	CMPulsarURLEnvKey = "CM_PULSAR_URL"
	CMAuthKeyEnvKey   = "CM_AUTH_KEY"
)

type CMUserOption struct {
	// 门户api地址
	APIHost string
	// 门户apikey
	APIKey string
	// pulsar地址
	PulsarURL string
	// jwt key
	AuthKey string
}

func GetCMUserOption() (*CMUserOption, error) {
	host := os.Getenv(CMAPIHostEnvKey)
	key := os.Getenv(CMAPIKeyEnvKey)
	pulsarUrl := os.Getenv(CMPulsarURLEnvKey)
	authKey := os.Getenv(CMAuthKeyEnvKey)

	if host == "" {
		return nil, fmt.Errorf("CM_API_HOST not set")
	}

	if key == "" {
		return nil, fmt.Errorf("CM_API_KEY not set")
	}

	if pulsarUrl == "" {
		return nil, fmt.Errorf("CM_PULSAR_URL not set")
	}

	if authKey == "" {
		return nil, fmt.Errorf("CM_AUTH_KEY not set")
	}

	return &CMUserOption{
		APIHost:   host,
		APIKey:    key,
		PulsarURL: pulsarUrl,
		AuthKey:   authKey,
	}, nil
}

type CMUserService struct {
	host         string
	apiKey       string
	lastSyncTime time.Time
	rdb          *databases.RDBInstance
	tokenAuth    *jwtauth.JWTAuth
}

func InitCMUserService(rdb *databases.RDBInstance, apiHost, apiKey, authKey string) (*CMUserService, error) {
	once.Do(func() {
		instance = NewCMUserService(rdb, apiHost, apiKey, authKey)
	})

	cm, ok := GetCMUserService(context.Background())

	if !ok {
		return nil, fmt.Errorf("init ChinaMobile service failed")
	}

	return cm, nil
}

func NewCMUserService(rdb *databases.RDBInstance, apiHost, apiKey, authKey string) *CMUserService {

	return &CMUserService{
		apiKey:    apiKey,
		host:      apiHost,
		rdb:       rdb,
		tokenAuth: jwtauth.New(cmALGO, []byte(authKey), nil),
	}
}

func GetCMUserService(_ context.Context) (*CMUserService, bool) {
	return instance, instance != nil
}

func GetCMUserAuth(ctx context.Context) (*jwtauth.JWTAuth, bool) {
	s, ok := GetCMUserService(ctx)
	if !ok {
		return nil, ok
	}

	return s.tokenAuth, true
}

const (
	CMUserPlatform      = "ChinaMobile"
	CMUserAdd           = "add"
	CMUserChange        = "change"
	CMUserDelete        = "delete"
	CMUserChangeStatus  = "chgstatus"
	CMUserResetPassword = "resetpwd"
)

// CMUser是中移系统的用户信息结构
type CMUser struct {
	UserID         uint64 `json:"userId"`
	UserName       string `json:"userName"`
	Alias          string `json:"alias"`
	Password       string `json:"password"`
	Sex            int    `json:"sex"`
	Phone          string `json:"phone"`
	Email          string `json:"email"`
	Address        string `json:"address"`
	Status         int    `json:"status"`
	CreateID       uint64 `json:"createId"`
	CreateTime     string `json:"createTime"`
	UpdateTime     string `json:"updateTime"`
	UserPhotoID    uint64 `json:"userPhotoId"`
	OrgID          uint64 `json:"orgId"`
	OrgName        string `json:"orgName"`
	SourceType     int    `json:"sourceType"`
	UserAccount    string `json:"userAccount"`
	LoginTimes     int    `json:"loginTimes"`
	LastLoginTime  string `json:"lastLoginTime"`
	DepartmentId   string `json:"departmentId"`
	DepartmentName string `json:""`
}

func FromCMUser(cm CMUser) (*model.User, error) {
	user := &model.User{
		UserName: cm.UserName,
		Pwd:      cm.Password,
		Role:     model.RoleAdmin,
		Platform: CMUserPlatform,
	}
	if cm.Status == 1 {
		user.Status = model.UserStatusNormal
	}
	if cm.Status == -1 {
		user.Status = model.UserStatusDisabled
	}

	if cm.CreateTime != "" {
		createTime, err := time.Parse(time.DateTime, cm.CreateTime)
		if err != nil {
			return nil, err
		}

		user.CreatedAt = createTime.UnixMilli()
	} else {
		user.CreatedAt = time.Now().UnixMilli()
	}

	return user, nil

}

type CMUserList struct {
	Total int64    `json:"total"`
	Data  []CMUser `json:"rows"`
	Code  int      `json:"code"`
	Msg   string   `json:"msg"`
}

type CMUserMsg struct {
	OperationType string `json:"operationType"`
	User          CMUser `json:"user"`
	OperationTime string `json:"operationTime"`
}

func (m *CMUserMsg) String() string {
	return fmt.Sprintf("operation: %s happens on user: %s on %s", m.OperationType, m.User.UserName, m.OperationTime)
}

func (s *CMUserService) SyncAndUpsertAllUser(ctx context.Context) error {
	syncStart := time.Now()

	err := util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		userList, err := s.listUsers(oneCtx)

		if err != nil {
			return err
		}

		return s.upsertUsers(oneCtx, userList.Data)
	})

	if err != nil {
		return err
	}

	s.lastSyncTime = syncStart

	return nil
}

func (s *CMUserService) listUsers(ctx context.Context) (*CMUserList, error) {
	url := fmt.Sprintf("%s/manager/openapi/users", s.host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return nil, err
	}

	req.Header.Add("apikey", s.apiKey)

	resp, err := cmClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	userList := &CMUserList{}

	err = json.Unmarshal(data, userList)
	if err != nil {
		return nil, err
	}

	return userList, nil
}

func (s *CMUserService) StartSubscribeCMUserMsg(ctx context.Context, pulsarURL string) error {
	err := s.SyncAndUpsertAllUser(ctx)
	if err != nil {
		return errors.Wrap(err, "sync all users from ChinaMobile failed")
	}

	logging.Get().Info().Msg("ChinaMobile-SSO: Sync all user completed, start to handle user msg")

	client, err := mq.NewPulsalClient(func() (pulsar.ClientOptions, error) {
		return pulsar.ClientOptions{
			URL: pulsarURL,
		}, nil
	})

	if err != nil {
		return err
	}

	return client.SubscribeV2("persistent://central/portal/fouralInfo", "SSO-Security", s.handleCMUserMsg)
}

func (s *CMUserService) handleCMUserMsg(ctx context.Context, data []byte) error {

	logging.Get().Info().Str("data", string(data)).Msg("handling ChinaMobie msg")

	msg := &CMUserMsg{}

	err := json.Unmarshal(data, msg)
	if err != nil {
		return err
	}

	operationTime, err := time.Parse(time.DateTime, msg.OperationTime)
	if err != nil {
		return err
	}
	logging.Get().Debug().Msgf("receiving ChinaMobile user event, operationType: %s, operationTime: %s, username: %s", msg.OperationType, msg.OperationTime, msg.User.UserName)
	// if operation happens before the time we last sync all users, we do nothing
	if operationTime.Before(s.lastSyncTime) {
		logging.Get().Info().Msgf("ignore event happend before %s, operationTime: %s, operationType: %s, username: %s", s.lastSyncTime, msg.OperationTime, msg.OperationType, msg.User.UserName)
		return nil
	}

	mctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	switch msg.OperationType {
	case CMUserAdd:
		return s.upsertUser(mctx, msg.User)
	case CMUserDelete:
		return s.deleteUser(mctx, msg.User.UserName)
	case CMUserChangeStatus:
		var status int
		if msg.User.Status == 1 {
			status = model.UserStatusNormal
		}
		if msg.User.Status == -1 {
			status = model.UserStatusDisabled
		}
		return s.setUserStatus(mctx, msg.User.UserName, status)
	case CMUserChange:
		return s.upsertUser(mctx, msg.User)
	case CMUserResetPassword:
		return s.setUserPassword(mctx, msg.User.UserName, msg.User.Password)
	}
	return nil
}

func (s *CMUserService) upsertUsers(ctx context.Context, users []CMUser) error {
	// 获取默认权限
	modules, err := s.getDefaultAuth(ctx)
	if err != nil {
		return err
	}

	model := &model.User{}
	err = s.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, cm := range users {
			user, err := FromCMUser(cm)
			if err != nil {
				return err
			}
			user.ModuleID = modules
			user.Token = util.GenerateUUIDHex()

			err = tx.Model(model).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "username"}},
				DoUpdates: clause.AssignmentColumns([]string{"pwd", "rule", "status", "module_id"}),
			}).Create(user).Error
			if err != nil {
				return err
			}

		}

		return nil
	})

	return err
}

func (s *CMUserService) upsertUser(ctx context.Context, cm CMUser) error {
	// 获取默认权限
	modules, err := s.getDefaultAuth(ctx)
	if err != nil {
		return err
	}
	user, err := FromCMUser(cm)
	if err != nil {
		return err
	}
	user.ModuleID = modules
	user.Token = util.GenerateUUIDHex()

	err = s.rdb.Get().WithContext(ctx).Model(user).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "username"}},
		DoUpdates: clause.AssignmentColumns([]string{"pwd", "rule", "status", "module_id"}),
	}).Create(user).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("")
	}

	return err
}

func (s *CMUserService) deleteUser(ctx context.Context, username string) error {
	return s.rdb.Get().WithContext(ctx).Model(&model.User{}).Where("username = ?", username).Delete(&model.User{}).Error
}

func (s *CMUserService) setUserStatus(ctx context.Context, username string, status int) error {
	return s.rdb.Get().WithContext(ctx).Model(&model.User{}).Where("username = ?", username).Update("status", status).Error
}

func (s *CMUserService) setUserPassword(ctx context.Context, username string, password string) error {
	return s.rdb.Get().WithContext(ctx).Model(&model.User{}).Where("username = ?", username).Updates(map[string]interface{}{
		"pwd":                password,
		"last_change_pwd_at": time.Now().UnixMilli(),
	}).Error
}

func (s *CMUserService) getDefaultAuth(ctx context.Context) (string, error) {
	moduleIDs := make([]string, 0)
	conf, err := dal.GetConfig(ctx, s.rdb.GetReadDB(), model.ConfIdpLogin)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return "", err
		}
		moduleGroup, err := dal.GetAdminModuleGroup(ctx, s.rdb.GetReadDB())
		if err != nil {
			return "", err
		}
		for _, module := range moduleGroup {
			moduleIDs = append(moduleIDs, strconv.Itoa(module.Id))
		}

		modules, _ := json.Marshal(moduleIDs)
		return string(modules), nil
	}

	resp := &idp.LoginConfig{}
	err = json.Unmarshal(conf.Config, resp)
	if err != nil {
		return "", err
	}

	for _, v := range resp.DefaultAuth {
		moduleIDs = append(moduleIDs, strconv.Itoa(v.Id))
	}
	modules, _ := json.Marshal(moduleIDs)
	return string(modules), nil
}

type cmUserInfo struct {
	UserId   uint64 `json:"userId"`
	UserName string `json:"userName"`
	ModuleID string
	Role     string
	Status   int
}

func (s *CMUserService) Authenticate(ctx context.Context, token *jwt.Token) (*cmUserInfo, error) {
	if !token.Valid {
		return nil, errors.New("Invalid ChinaMobile token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("extract claim from ChinaMobile token failed")
	}
	userInfoString := cast.ToString(claims["userInfo"])
	if userInfoString == "" {
		return nil, errors.New("userInfo must be provided in token")
	}

	u := &cmUserInfo{}

	if err := json.Unmarshal([]byte(userInfoString), u); err != nil {
		return nil, errors.Wrap(err, "ChinaMobile token userInfo malformat")
	}

	exist, user, err := dal.SelectUser(ctx, s.rdb.GetReadDB(), u.UserName)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, errors.New("user not found")
	}

	if user.Status != model.UserStatusNormal {
		return nil, errors.New(fmt.Sprintf("user %s status unauthorized", u.UserName))
	}

	u.Role = user.Role
	u.ModuleID = user.ModuleID
	u.Status = user.Status
	return u, nil
}

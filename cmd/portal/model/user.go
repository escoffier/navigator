package model

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type User struct {
	ID          int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id"`   // 用户ID
	Name        string `gorm:"column:name" json:"name"`                // 用户名
	Pwd         string `gorm:"column:pwd" json:"-"`                    // 加密后的密码
	PwdString   string `gorm:"-" json:"pwd,omitempty"`                 // 明文密码
	Role        string `gorm:"column:role" json:"role"`                // 用户角色
	Mobile      string `gorm:"column:mobile" json:"mobile"`            // 手机号
	Comment     string `gorm:"column:comment" json:"comment"`          // 备注信息
	Status      string `gorm:"column:status" json:"status"`            // 账号状态，这一期不用
	PortalEmail string `gorm:"column:portal_email" json:"portalEmail"` // 登录邮箱
	// sourceCheck
	SourceCheckToken string `gorm:"column:source_check_token" json:"sourceCheckToken"` // sourceCheck的访问令牌
	SourceCheckEmail string `gorm:"column:source_check_email" json:"sourceCheckEmail"` // sourceCheck的登录邮箱
	SourceCheckPwd   string `gorm:"column:source_check_pwd" json:"-"`                  // sourceCheck的登录密码
	// codesec使用
	CodesecAk    string `gorm:"column:codesec_ak" json:"codesecAk"`       // 也就是 codesec的UserUuid
	CodesecSk    string `gorm:"column:codesec_sk" json:"codesecSk"`       // 也就是 codesec的AccessSecret
	CodesecPwd   string `gorm:"column:codesec_pwd" json:"-"`              // codesec的登录密码
	CodesecEmail string `gorm:"column:codesec_email" json:"codesecEmail"` // codesec的登录邮箱
	// 领航使用
	TensorEmail string `gorm:"column:tensor_email" json:"tensorEmail"` // tensor的登录邮箱
	TensorPwd   string `gorm:"column:tensor_pwd" json:"tensorPwd"`     // tensor的登录密码

	Token      string `gorm:"column:token" json:"-"`        // jwt token
	TokenExpAt int64  `gorm:"column:token_exp_at" json:"-"` // jwt token过期时间

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	DeletedAt int64 `gorm:"column:deleted_at;default:0" json:"deletedAt"`            // milliseconds
}

type LoginResponse struct {
	ID          int64  `json:"id"`
	PortalEmail string `json:"portalEmail"`
	Token       string `json:"token"`
}

func (u *User) Same(b *User) bool {
	same := u.PortalEmail == b.PortalEmail &&
		u.Mobile == b.Mobile &&
		u.Status == b.Status &&
		u.Name == b.Name &&
		u.Role == b.Role &&
		u.SourceCheckToken == b.SourceCheckToken &&
		u.SourceCheckEmail == b.SourceCheckEmail &&
		u.CodesecAk == b.CodesecAk &&
		u.CodesecSk == b.CodesecSk &&
		u.CodesecEmail == b.CodesecEmail &&
		u.TensorEmail == b.TensorEmail &&
		u.TensorPwd == b.TensorPwd &&
		u.SourceCheckPwd == b.SourceCheckPwd &&
		u.CodesecPwd == b.CodesecPwd
	return same
}

type SearchUserParam struct {
	ID          int64
	PortalEmail string
	Mobile      string
	Status      string
	Name        string
	AuthCode    string
	Filter      *imagesec.Filter
}

type UpdateUserParam struct {
	ID      int64
	Updater map[string]interface{}
}

func (u *User) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"mobile":  u.Mobile,
		"comment": u.Comment,
		"name":    u.Name,
	}
	return updater
}

func (u *User) Serialize() {
	u.Name = strings.TrimSpace(u.Name)
	u.Comment = strings.TrimSpace(u.Comment)
	u.PwdString = strings.TrimSpace(u.PwdString)
	u.Mobile = strings.TrimSpace(u.Mobile)
	u.Pwd = u.EncryptPwd(u.PwdString)

	if u.SourceCheckEmail == "" {
		u.SourceCheckEmail = u.PortalEmail
	}
	if u.CodesecEmail == "" {
		u.CodesecEmail = u.PortalEmail
	}
	if u.TensorEmail == "" {
		u.TensorEmail = u.PortalEmail
	}
	if u.SourceCheckPwd == "" {
		u.SourceCheckPwd = u.PwdString
	}
	if u.CodesecPwd == "" {
		u.CodesecPwd = u.PwdString
	}
	if u.TensorPwd == "" {
		u.TensorPwd = u.PwdString
	}
}

func (u *User) Deserialize() {
}

func (u *User) Check() error {
	if err := u.CheckPassword(); err != nil {
		return err
	}

	if err := u.CheckEmail(); err != nil {
		return err
	}
	return nil
}

func (u *User) TableName() string {
	return "portal_user"
}

func (u *User) EncryptPwd(pwd string) string {
	encrypted, err := util.AesEncryptCBC([]byte(pwd), []byte(util.DownloadFileKey))
	if err != nil {
		return ""
	}

	return hex.EncodeToString(encrypted)
}

func (u *User) CheckEmail() error {
	email := strings.TrimSpace(u.PortalEmail)
	if email == "" {
		return errors.New("email cannot be empty")
	}

	// 邮箱正则表达式遵循RFC 5322标准
	pattern := `^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`
	reg := regexp.MustCompile(pattern)
	if !reg.MatchString(email) {
		return errors.New("invalid email format")
	}

	// 额外检查域名部分不能以连字符开头/结尾
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errors.New("invalid email format")
	}
	domainPart := parts[1]
	if strings.HasPrefix(domainPart, "-") || strings.HasSuffix(domainPart, "-") {
		return errors.New("domain cannot start or end with hyphen")
	}

	return nil
}

func (u *User) CheckPassword() error {
	// 至少 8 个字符
	password := u.PwdString
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	// 至少包含一个数字
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}

	// 至少包含一个字母
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(password)
	if !hasLetter {
		return errors.New("password must contain at least one letter")
	}

	// 至少包含一个特殊字符
	hasSpecialChar := regexp.MustCompile(`[!@#$%^&*()_+{}:;<>,.?~\\-]`).MatchString(password)
	if !hasSpecialChar {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

type AuthCode struct {
	AuthCode string `json:"authCode"` // 授权码
	UserID   int64  `json:"userID"`   // 用户 ID
}

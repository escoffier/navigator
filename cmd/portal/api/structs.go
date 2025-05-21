package api

import (
	model "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
)

type User struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"` // typo; role
	Mobile      string `json:"mobile"`
	Email       string `json:"email"` // 三个平台都使用 email
	Comment     string `json:"comment"`
	Status      string `json:"status"` // 账号状态，这一期不用
	PortalEmail string `json:"portalEmail"`
	// sourceCheck
	SourceCheckToken string `json:"sourceCheckToken"`
	SourceCheckEmail string `json:"sourceCheckEmail"`
	// codesec使用
	CodesecAk    string `json:"codesecAk"` // 也就是 codesec的UserUuid
	CodesecSk    string `json:"codesecSk"`
	CodesecEmail string `json:"codesecEmail"`
	// 领航使用
	TensorEmail string `json:"tensorEmail"`
	Token       string `json:"-"`
	TokenExpAt  int64  `json:"-"`

	CreatedAt int64 `json:"createdAt"` // milliseconds
	UpdatedAt int64 `json:"updatedAt"` // milliseconds
}

// ConvertModelUserToAPI 将model.User转换为api.User
func ConvertModelUserToAPI(modelUser *model.User) *User {
	if modelUser == nil {
		return nil
	}

	return &User{
		ID:               modelUser.ID,
		Name:             modelUser.Name,
		Role:             modelUser.Role,
		Mobile:           modelUser.Mobile,
		Email:            modelUser.SourceCheckEmail,
		Comment:          modelUser.Comment,
		Status:           modelUser.Status,
		PortalEmail:      modelUser.PortalEmail,
		SourceCheckToken: modelUser.SourceCheckToken,
		SourceCheckEmail: modelUser.SourceCheckEmail,
		CodesecAk:        modelUser.CodesecAk,
		CodesecSk:        modelUser.CodesecSk,
		CodesecEmail:     modelUser.CodesecEmail,
		TensorEmail:      modelUser.TensorEmail,
		Token:            modelUser.Token,
		TokenExpAt:       modelUser.TokenExpAt,
		CreatedAt:        modelUser.CreatedAt,
		UpdatedAt:        modelUser.UpdatedAt,
	}
}

package token

import (
	"context"

	portal "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
)

type Payload struct {
	ID               int64  `json:"id"`
	Mobile           string `json:"mobile"`
	PortalEmail      string `json:"portalEmail"`
	Role             string `json:"role"`
	Status           string `json:"status"`
	SourceCheckToken string `json:"sct"`
	CodesecKey       string `json:"ck"`
	CodesecSecret    string `json:"cs"`
}

// Manager issues token to user and verify token
type Manager interface {
	IssueTo(Payload) (string, error)
	Verify(string) (Payload, error)
	Exp() int64
}

func GetPayload(ctx context.Context) Payload {
	em := Payload{}
	p := ctx.Value("Payload")
	payload, ok := p.(Payload)
	if !ok {
		return em
	}
	return payload
}

type UserDal interface {
	GetUser(ctx context.Context, param portal.SearchUserParam) (*portal.User, error)
	UpdateUser(ctx context.Context, up portal.UpdateUserParam) error
}

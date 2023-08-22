package token

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Payload struct {
	Username   string         `json:"username"`
	Account    string         `json:"account"`
	Role       model.RoleType `json:"role"`
	Platform   string         `json:"platform "`
	ModuleID   string         `json:"moduleID"`
	External   bool           `json:"external"`
	Status     int            `json:"status"`
	Eigenvalue string         `json:"eigenvalue"`
}

// Manager issues token to user and verify token
type Manager interface {
	// IssueTo issues a token a User, return error if issuing process failed
	IssueTo(info Payload, expiresIn time.Duration) (string, error)

	// Verify verifies a token, and return a user info if it's a valid token, otherwise return error
	Verify(string) (*Payload, error)
}

package radius

import (
	"context"
	"errors"
	"fmt"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	ErrUserPasswordNotMatch = errors.New("user password not match")
)

func Login(ctx context.Context, account, password, state string, conf *model.RadiusServerConf) (string, error) {
	packet := radius.New(radius.CodeAccessRequest, []byte(conf.Secret))
	err := rfc2865.UserName_SetString(packet, account)
	if err != nil {
		return "", err
	}

	err = rfc2865.UserPassword_SetString(packet, password)
	if err != nil {
		return "", err
	}

	if state != "" {
		err = rfc2865.State_SetString(packet, state)
		if err != nil {
			return "", err
		}
	}

	var client *radius.Client
	if conf.Network == "udp" {
		client = radius.DefaultClient
	} else {
		client = &radius.Client{
			Retry:           time.Second,
			MaxPacketErrors: 10,
			Net:             "tcp",
		}
	}
	response, err := client.Exchange(ctx, packet, fmt.Sprintf("%s:%d", conf.Addr, conf.Port))
	if err != nil {
		return "", err
	}

	logging.GetLogger().Debug().Msgf("code:%s", response.Code)

	if response.Code == radius.CodeAccessAccept {
		return "", nil
	}

	if response.Code == radius.CodeAccessChallenge {
		return rfc2865.State_GetString(response), nil
	}

	return "", ErrUserPasswordNotMatch
}

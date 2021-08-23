package openapiauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	s *Service
)

func initService(t *testing.T) {
	logging.GetLogger().Level(zerolog.DebugLevel)
	cli := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})

	if err := cli.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}

	s = newService(nil, cli)
}

func TestService_ObtainJWTToken(t *testing.T) {
	initService(t)
	token, err := s.ObtainToken(context.TODO(), "testUser")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)
}

func TestService_GetUsernameByToken(t *testing.T) {
	initService(t)
	token, err := s.ObtainToken(context.TODO(), "testUser")
	if err != nil {
		t.Fatal(err)
	}

	username, err := s.GetUsernameByToken(context.TODO(), token)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "testUser", username)

	_, err = s.GetUsernameByToken(context.TODO(), "nonsense")
	assert.Equal(t, true, err == ErrInvalidToken)

	_, err = s.ObtainToken(context.TODO(), "testUser")
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.GetUsernameByToken(context.TODO(), token)
	assert.Equal(t, true, err == nil)
}

func TestJsonUnmarshal(t *testing.T) {
	b := []byte(`{"SourceIPs":"","Namespace":"","ResourceName":"","ResourceKind":null,"Verb":null,"ResponseStatusCode":null,"Stage":"ResponseComplete"}`)
	var m map[string]string
	var err = json.Unmarshal(b, &m)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range m {
		t.Log(k, v, v == "")
	}
}

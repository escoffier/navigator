package captcha

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dchest/captcha"
	"github.com/go-redis/redis/v8"
	"github.com/sony/gobreaker"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type Conf struct {
	CaptchaWidth      int
	CaptchaHeight     int
	CaptchaLen        int
	CaptchaExpiration time.Duration
}

var (
	DefaultConf = &Conf{
		CaptchaWidth:      240,
		CaptchaHeight:     80,
		CaptchaLen:        4,
		CaptchaExpiration: time.Minute,
	}
)

type Service struct {
	redisCli *redis.Client
	conf     *Conf
	breaker  *gobreaker.CircuitBreaker
}

var (
	instance atomic.Value // *Service
	once     sync.Once
)

func Init(redisCli *redis.Client, conf *Conf) error {
	if redisCli == nil || conf == nil {
		return errors.New("unexpected empty pointer")
	}

	once.Do(func() {
		var service = newService(redisCli, conf)
		captcha.SetCustomStore(service)
		instance.Store(service)
	})

	return nil
}

func GetService() (*Service, bool) {
	service := instance.Load()
	if service == nil {
		return nil, false
	}

	return service.(*Service), true
}

func newService(redisCli *redis.Client, conf *Conf) *Service {
	breaker := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "captcha",
		MaxRequests: 3,
		Interval:    0,
		Timeout:     time.Second * 5,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			// As long as there is a failure to fuse
			return counts.ConsecutiveFailures >= 1
		},
	})

	return &Service{
		redisCli: redisCli,
		conf:     conf,
		breaker:  breaker,
	}
}

const (
	defaultOneTimeout = time.Millisecond * 500
	captchaPrefix     = "captcha@"
)

func (s *Service) Set(id string, digits []byte) {
	_, err := s.breaker.Execute(func() (interface{}, error) {
		oneCtx, oneCancel := context.WithTimeout(context.Background(), defaultOneTimeout)
		defer oneCancel()
		return nil, s.redisCli.Set(oneCtx, getRedisKey(id), base64.StdEncoding.EncodeToString(digits), s.conf.CaptchaExpiration).Err()
	})

	// write captcha failed
	if err != nil {
		logging.GetLogger().Warn().Err(err)
	}
}

// Get returns stored digits for the captcha id. Clear indicates
// whether the captcha must be deleted from the store.
func (s *Service) Get(id string, clear bool) (digits []byte) {
	result, err := s.breaker.Execute(func() (interface{}, error) {
		oneCtx, oneCancel := context.WithTimeout(context.Background(), defaultOneTimeout)
		defer oneCancel()

		result, err := s.redisCli.Get(oneCtx, getRedisKey(id)).Result()
		if err != nil {
			if err == redis.Nil {
				return "", nil
			}
			return nil, err
		}

		if clear {
			err = s.redisCli.Del(oneCtx, fmt.Sprintf("%s%s", captchaPrefix, id)).Err()
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("failed to delete the captcha after get")
			}
		}

		return result, nil
	})

	if err != nil {
		logging.GetLogger().Warn().Err(err)
		return nil
	}

	digits, err = base64.StdEncoding.DecodeString(result.(string))
	if err != nil {
		logging.GetLogger().Err(err).Msg("base64 decode fail")
		return nil
	}

	return digits
}

func (s *Service) CreateCaptcha() string {
	return captcha.NewLen(s.conf.CaptchaLen)
}

func (s *Service) IsBreakerClosed() bool {
	return s.breaker.State() == gobreaker.StateClosed
}

func (s *Service) Reload(id string) bool {
	return captcha.Reload(id)
}

func (s *Service) WriteImage(w io.Writer, id string) error {
	return captcha.WriteImage(w, id, s.conf.CaptchaWidth, s.conf.CaptchaHeight)
}

func (s *Service) GetCaptchaString(id string) string {
	digits := s.Get(id, false)
	ns := make([]byte, len(digits))
	for i := range ns {
		ns[i] = digits[i] + '0'
	}

	return string(ns)
}

func (s *Service) Verify(id, digits string) bool {
	return captcha.VerifyString(id, digits)
}

func getRedisKey(key string) string {
	return fmt.Sprintf("%s%s", captchaPrefix, key)
}

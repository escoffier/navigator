package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/go-redis/redis/v8"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/palace/pkg/apiinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/palace/pkg/association"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/mqtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"gitlab.com/security-rd/go-pkg/databases"
	_ "go.uber.org/automaxprocs"
	"google.golang.org/protobuf/proto"
)

const (
	associatedSubject = "tensorsec_podcontainer_events"
	queueName         = "tensorsec_holmes_palace"
)

var (
	stanConn              *mqtools.StanConn
	rdb                   *databases.RDBInstance
	redisCli              *redis.Client
	associationDispatcher *association.EventDispatcher
)

func initAssociationDispatchers(rdb *databases.RDBInstance) error {
	var err error
	rulesManager := echelper.NewRulesManager(rdb, 5*time.Minute)
	associationDispatcher, err = association.NewEventDispatcher(association.DispatchConfig{
		ParallelNum: 2,
	},
		association.Configuration{
			WindowDivisionLatency: 10 * time.Minute,
			BuildInterval:         1 * time.Minute,
		},
		rdb,
		rulesManager,
	)
	return err
}

func initRedis() (err error) {
	redisEndpoint := os.Getenv("REDIS_CLUSTER_URL")
	if redisEndpoint == "" {
		panic("REDIS_ENDPOINT env variable not set")
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")
	if redisPassword == "" {
		panic("REDIS_PASSWORD env variable not set")
	}

	sa := strings.Split(redisEndpoint, ",")
	redisCli, err = redistools.NewTensorRedisClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      redisPassword,
		DB:            0,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("Failed to get redis client")
		return
	}
	return
}

func initDB() error {
	var err error
	rdb, err = databases.NewRDBWithMySQLByEnv(context.Background())
	if err != nil {
		logging.GetLogger().Err(err).Msg("Init db error")
		return err
	}
	return nil
}

func initStan(podName string) error {
	stanURL := os.Getenv("STAN_URL")
	if stanURL == "" {
		logging.GetLogger().Warn().Msg("env STAN_URL not found")
		return errors.New("get STAN address failed.")
	}
	clusterID := os.Getenv("STAN_CLUSTER_ID")
	if clusterID == "" {
		logging.GetLogger().Warn().Msg("env STAN_CLUSTER_ID not found")
		return errors.New("get STAN_CLUSTER_ID failed.")
	}

	stanConn = mqtools.NewStanConn(func() (stan.Conn, error) {
		nc, err := nats.Connect(fmt.Sprintf("nats://%s", stanURL), nats.MaxReconnects(5), nats.ReconnectBufSize(64*1024), nats.ReconnectWait(500*time.Millisecond))
		if err != nil {
			return nil, err
		}
		stanc, err := stan.Connect(clusterID, getClientID(podName), stan.NatsConn(nc))
		return stanc, err
	})

	return nil
}

var runes = []rune{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
}

func getClientID(podName string) string {
	b := strings.Builder{}
	for _, by := range podName {
		if (by >= 'a' && by <= 'z') || (by >= 'A' && by <= 'Z') || (by >= '0' && by <= '9') || by == '-' || by == '_' {
			b.WriteRune(by)
		} else {
			b.WriteRune(runes[rand.Intn(len(runes))])
		}
	}
	return b.String()
}
func handleAssocatedEvents(m *stan.Msg) {
	var data outputs.Response
	err := proto.Unmarshal(m.Data, &data)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("unmarshal association events error. data: %s", m.Data)
		return
	}
	originEvent := association.NewOriginEventFrom("ATT&CK", &data)

	err = associationDispatcher.ProcessEvent(context.Background(), originEvent)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("process event error. originEvent: %+v", originEvent)
	}
}

func main() {
	err := initDB()
	if err != nil {
		logging.GetLogger().Err(err).Msg("init rdb error")
		panic(err)
	}
	err = initRedis()
	if err != nil {
		logging.GetLogger().Err(err).Msg("init redis error")
		panic(err)
	}
	err = initAssociationDispatchers(rdb)
	if err != nil {
		logging.GetLogger().Err(err).Msg("init AssociationDispatchers error")
		panic(err)
	}

	podName := os.Getenv("MY_POD_NAME")
	if podName == "" {
		podName = "Unknown"
	}
	err = initStan(podName)
	if err != nil {
		logging.GetLogger().Err(err).Msg("init stan error")
		panic(err)
	}
	if err := apiinfo.InitDB(rdb); err != nil {
		logging.GetLogger().Err(err).Msg("init db error")
		panic(err)
	}

	// wait for the establishment of connection to stan
	stanconn := waitForStannConn()

	associationSub, err := stanconn.QueueSubscribe(associatedSubject, queueName, handleAssocatedEvents, stan.StartWithLastReceived(), stan.DurableName(queueName))

	if err != nil {
		logging.GetLogger().Err(err).Msg("subscribe association error.")
		panic(err)
	}
	defer associationSub.Close()

	// api discovery
	apiInfoSub, err := stanconn.Subscribe(apiinfo.APISubject, func(msg *stan.Msg) {
		apiinfo.Process(msg)
	}, stan.StartWithLastReceived(), stan.DurableName(apiinfo.APISubject))
	if err != nil {
		logging.GetLogger().Err(err).Msg("subscribe apiInfo error.")
	} else {
		defer apiInfoSub.Close()
	}

	// imErr := immune.Init(redisCli, stanconn)
	// if imErr != nil {
	// 	logging.GetLogger().Err(imErr).Msg("init immune module error")
	// } else {
	// 	werr := immune.Watch()
	// 	if werr != nil {
	// 		logging.GetLogger().Err(werr).Msg("init immune module watch error")
	// 	} else {
	// 		commandSub, err := stanconn.Subscribe(immune.CommandSubject, immune.CommandHandler, stan.StartWithLastReceived(), stan.DurableName(immune.CommandSubject))
	// 		if err != nil {
	// 			logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to management topic")
	// 			panic(err)
	// 		}
	// 		defer commandSub.Close()

	// 		fileSub, err := stanconn.Subscribe(immune.FileRWSubject, func(m *stan.Msg) {
	// 			immune.UpdateProfile(mainCtx, m, model.SecurityKindApparmor)
	// 		}, stan.StartWithLastReceived(), stan.DurableName(immune.FileRWSubject))
	// 		if err != nil {
	// 			logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to apparmor topic")
	// 		} else {
	// 			defer fileSub.Close()
	// 		}

	// 		cmdSub, err := stanconn.Subscribe(immune.CmdSubject, func(m *stan.Msg) {
	// 			logging.GetLogger().Info().Msg("Received new command whitelist message")
	// 			immune.UpdateProfile(mainCtx, m, model.SecurityKindCommandWhitelist)
	// 		}, stan.StartWithLastReceived(), stan.DurableName(immune.CmdSubject))
	// 		if err != nil {
	// 			logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to command whitelist topic")
	// 		} else {
	// 			defer cmdSub.Close()
	// 		}

	// 		syscallSub, err := stanconn.Subscribe(immune.SyscallSubject, func(m *stan.Msg) {
	// 			logging.GetLogger().Info().Msg("Received new seccomp message")
	// 			immune.UpdateProfile(mainCtx, m, model.SecurityKindSeccomp)
	// 		}, stan.StartWithLastReceived(), stan.DurableName(immune.CmdSubject))
	// 		if err != nil {
	// 			logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to seccomp topic")
	// 			panic(err)
	// 		}
	// 		defer syscallSub.Close()
	// 	}
	// }

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}

func waitForStannConn() stan.Conn {
	if !stanConn.Connected() {
		ticker := time.NewTicker(5 * time.Second)
		toStop := false
		for !toStop {
			select {
			case <-stanConn.Notif():
				toStop = true
				ticker.Stop()
				break
			case <-ticker.C:
				if stanConn.Connected() {
					toStop = true
					ticker.Stop()
					break
				}
			}
		}
	}
	stanconn, _ := stanConn.Conn()
	return stanconn
}

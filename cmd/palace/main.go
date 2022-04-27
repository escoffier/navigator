package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/go-redis/redis/v8"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/palace/pkg/apiinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/palace/pkg/association"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	_ "go.uber.org/automaxprocs"
	"google.golang.org/protobuf/proto"
)

const (
	associatedSubject = "ivan_podcontainer_events"
	groupID           = "ivan_holmes_palace"
)

var (
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
		logging.Get().Err(err).Msg("Failed to get redis client")
		return
	}
	return
}

func initDB() error {
	var err error
	rdb, err = databases.NewRDBWithMySQLByEnv(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("Init db error")
		return err
	}
	return nil
}

func handleAssocatedEvents(ctx context.Context, m kafka.Message) error {
	var data outputs.Response
	err := proto.Unmarshal(m.Value, &data)
	if err != nil {
		logging.Get().Err(err).Str("data", string(m.Value)).Msg("unmarshal association events error")
		return err
	}
	originEvent := association.NewOriginEventFrom("ATT&CK", &data)

	err = associationDispatcher.ProcessEvent(context.Background(), originEvent)
	if err != nil {
		logging.Get().Err(err).Msgf("process event error. originEvent: %+v", originEvent)
		return err
	}
	return nil
}

func main() {
	err := initDB()
	if err != nil {
		logging.Get().Err(err).Msg("init rdb error")
		panic(err)
	}
	err = initRedis()
	if err != nil {
		logging.Get().Err(err).Msg("init redis error")
		panic(err)
	}
	err = initAssociationDispatchers(rdb)
	if err != nil {
		logging.Get().Err(err).Msg("init AssociationDispatchers error")
		panic(err)
	}

	mqFactory := mq.GetClientFactory()
	mqReader, err := mqFactory.Reader(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("init mq reader error")
		panic(err)
	}
	if err := apiinfo.InitDB(rdb); err != nil {
		logging.Get().Err(err).Msg("init db error")
		panic(err)
	}

	err = mqReader.Subscribe(associatedSubject, groupID, handleAssocatedEvents)

	if err != nil {
		logging.Get().Err(err).Msg("subscribe association error.")
		panic(err)
	}

	// api discovery
	err = mqReader.Subscribe(apiinfo.APISubject, groupID, func(ctx context.Context, m kafka.Message) error {
		apiinfo.Process(m)
		return nil
	})
	if err != nil {
		logging.Get().Err(err).Msg("subscribe apiInfo error.")
	}

	// imErr := immune.Init(redisCli, stanconn)
	// if imErr != nil {
	// 	logging.Get().Err(imErr).Msg("init immune module error")
	// } else {
	// 	werr := immune.Watch()
	// 	if werr != nil {
	// 		logging.Get().Err(werr).Msg("init immune module watch error")
	// 	} else {
	// 		commandSub, err := stanconn.Subscribe(immune.CommandSubject, immune.CommandHandler, stan.StartWithLastReceived(), stan.DurableName(immune.CommandSubject))
	// 		if err != nil {
	// 			logging.Get().Fatal().Err(err).Msg("Failed to subscribe to management topic")
	// 			panic(err)
	// 		}
	// 		defer commandSub.Close()

	// 		fileSub, err := stanconn.Subscribe(immune.FileRWSubject, func(m *stan.Msg) {
	// 			immune.UpdateProfile(mainCtx, m, model.SecurityKindApparmor)
	// 		}, stan.StartWithLastReceived(), stan.DurableName(immune.FileRWSubject))
	// 		if err != nil {
	// 			logging.Get().Fatal().Err(err).Msg("Failed to subscribe to apparmor topic")
	// 		} else {
	// 			defer fileSub.Close()
	// 		}

	// 		cmdSub, err := stanconn.Subscribe(immune.CmdSubject, func(m *stan.Msg) {
	// 			logging.Get().Info().Msg("Received new command whitelist message")
	// 			immune.UpdateProfile(mainCtx, m, model.SecurityKindCommandWhitelist)
	// 		}, stan.StartWithLastReceived(), stan.DurableName(immune.CmdSubject))
	// 		if err != nil {
	// 			logging.Get().Fatal().Err(err).Msg("Failed to subscribe to command whitelist topic")
	// 		} else {
	// 			defer cmdSub.Close()
	// 		}

	// 		syscallSub, err := stanconn.Subscribe(immune.SyscallSubject, func(m *stan.Msg) {
	// 			logging.Get().Info().Msg("Received new seccomp message")
	// 			immune.UpdateProfile(mainCtx, m, model.SecurityKindSeccomp)
	// 		}, stan.StartWithLastReceived(), stan.DurableName(immune.CmdSubject))
	// 		if err != nil {
	// 			logging.Get().Fatal().Err(err).Msg("Failed to subscribe to seccomp topic")
	// 			panic(err)
	// 		}
	// 		defer syscallSub.Close()
	// 	}
	// }

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}

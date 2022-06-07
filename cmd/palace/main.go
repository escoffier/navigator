package main

import (
	"context"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/go-redis/redis/v8"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/palace/pkg/apiinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/palace/pkg/association"
	"gitlab.com/piccolo_su/vegeta/cmd/palace/pkg/ecenter"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/pb"
	_ "go.uber.org/automaxprocs"
	"google.golang.org/protobuf/proto"
)

var (
	rdb                   *databases.RDBInstance
	redisCli              *redis.Client
	associationDispatcher *association.EventDispatcher
	ecenterHandler        *ecenter.EcHandler
	uuidGen               *uuid.Generator
)

func init() {
	rand.Seed(time.Now().UnixNano())

	var err error
	uuidGen, err = uuid.NewGenerator()
	if err != nil {
		logging.Get().Err(err).Msg("init uuid gen error")
	}
}

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
	redisCli, err = cache.NewRedis()
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

func handlePodContainerEvents(ctx context.Context, m kafka.Message) error {
	var data outputs.Response
	err := proto.Unmarshal(m.Value, &data)
	if err != nil {
		logging.Get().Err(err).Str("data", string(m.Value)).Msg("unmarshal association events error")
		return err
	}
	var uuid uint64
	if uuidGen == nil {
		uuid = rand.Uint64()
	} else {
		uuid = uuidGen.GenerateUUID()
	}
	data.OutputFields[rtdetect.KeyUuid] = strconv.FormatUint(uuid, 10)
	originEvent := association.NewOriginEventFrom("ATT&CK", &data)

	err = associationDispatcher.ProcessEvent(context.Background(), originEvent)
	if err != nil {
		logging.Get().Err(err).Msgf("process event error. originEvent: %+v", originEvent)
		return err
	}

	err = ecenterHandler.Input(context.Background(), &data)
	if err != nil {
		logging.Get().Err(err).Msgf("process event in echandler error. originEvent: %+v", originEvent)
		return err
	}
	return nil
}

func handleDriftEvents(ctx context.Context, m kafka.Message) error {
	var data pb.SendNotificationReq
	err := proto.Unmarshal(m.Value, &data)
	if err != nil {
		logging.Get().Err(err).Str("data", string(m.Value)).Msg("unmarshal drift events error")
		return err
	}
	logging.Get().Debug().Msgf("drift event: %+v", data)

	err = ecenterHandler.InputReq(ctx, &data)
	if err != nil {
		logging.Get().Err(err).Msgf("process event in echandler error. originEvent: %+v", data)
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

	ecli, err := echelper.NewGRPCClientFromEnv()
	if err != nil {
		logging.Get().Err(err).Msg("init ecenter err")
		panic(err)
	}

	concurency := int64(2)
	cstr := os.Getenv(EnvECenterConcurrency)
	if len(cstr) > 0 {
		c, err := strconv.ParseInt(cstr, 10, 64)
		if err == nil && c > 0 {
			concurency = c
		}
	}

	ecenterHandler, err = ecenter.NewEcHandler(100, int(concurency), ecli)
	if err != nil {
		logging.Get().Err(err).Msg("init ecenter handler err")
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

	err = mqReader.Subscribe(associatedSubject, getGroupIDOfTopic(associatedSubject), handlePodContainerEvents)

	if err != nil {
		logging.Get().Err(err).Msg("subscribe association error.")
		panic(err)
	}

	// api discovery
	err = mqReader.Subscribe(apiinfo.APISubject, getGroupIDOfTopic(apiinfo.APISubject), func(ctx context.Context, m kafka.Message) error {
		apiinfo.Process(m)
		return nil
	})
	if err != nil {
		logging.Get().Err(err).Msg("subscribe apiInfo error.")
	}

	// drift event
	err = mqReader.Subscribe(model.SubjectOfDriftEvent, getGroupIDOfTopic(model.SubjectOfDriftEvent), handleDriftEvents)
	if err != nil {
		logging.Get().Err(err).Msg("subscribe SubjectOfDriftEvent error.")
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

package config

import (
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/util"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	MutationPGDB   *gorm.DB
	MutationK8sCli *kubernetes.Clientset
)


func InitMutationConfig() error {
	var err error
	MutationPGDB, err = util.InitPGDB()
	if err != nil {
		return errors.Wrap(err, "failed to init db")
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return errors.Wrap(err, "failed to init k8s config")
	}
	MutationK8sCli, err = kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "failed to init k8s clientset")
	}

	logging.GetLogger().Info().Msg("finished to init microseg mutation webhook")
	return nil
}

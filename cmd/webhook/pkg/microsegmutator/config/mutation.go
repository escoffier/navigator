package config

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/util"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	MutationCfg    *MutationConfig
	MutationPGDB   *gorm.DB
	MutationK8sCli *kubernetes.Clientset
)

type MutationConfig struct {
	RunMode  string        `mapstructure:"runMode"` // dev or prod
	PgMaster util.PGMaster `mapstructure:"pgMaster"`
	CertFile string        `mapstructure:"certFile"`
	CertKey  string        `mapstructure:"certKey"`
}

func InitMutationConfig(configName string) error {
	MutationCfg = &MutationConfig{}
	viper.AutomaticEnv()
	viper.SetConfigName(configName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(processors.ConfigBasePath)
	err := viper.ReadInConfig()
	if err != nil {
		return errors.Wrap(err, "failed to read config")
	}
	err = viper.Unmarshal(MutationCfg)
	if err != nil {
		return errors.Wrap(err, "unable to decode into struct")
	}

	if MutationCfg.RunMode == "dev" {
		logrus.SetReportCaller(true)
		logrus.SetLevel(logrus.DebugLevel)
	}

	MutationPGDB, err = util.InitPGDB(MutationCfg.PgMaster)
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

	logrus.Infof("init application with config: %+v", MutationCfg)
	return nil
}

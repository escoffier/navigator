package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	rdbPVC       = "rdb-pvc"
	rdbPod       = "rdb-pod"
	rdbDataPath  = "rdb-data-path"
	rdbContainer = "rdb-container"
)

type RDBOpts struct {
	PVC       string
	Pod       string
	DataPath  string
	Container string
}

func NewDefaultRDBOpts() *RDBOpts {
	return &RDBOpts{
		PVC:       "tensorsec-postgres-pvc",
		Pod:       "tensorsec-postgres-pod",
		DataPath:  "/data",
		Container: "mysql",
	}
}
func GetRDBOpts(cmd *cobra.Command) *RDBOpts {
	return &RDBOpts{
		PVC:       viper.GetString(rdbPVC),
		Pod:       viper.GetString(rdbPod),
		DataPath:  viper.GetString(rdbDataPath),
		Container: viper.GetString(rdbContainer),
	}
}

func AddRDBFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultRDBOpts()
	cmd.PersistentFlags().String(rdbPVC, defaultOpts.PVC, "rdb kubernetes PVC")
	cmd.PersistentFlags().String(rdbPod, defaultOpts.Pod, "rdb kubernetes Pod")
	cmd.PersistentFlags().String(rdbDataPath, defaultOpts.DataPath, "rdb data path")
	cmd.PersistentFlags().String(rdbContainer, defaultOpts.Container, "rdb container")
	for _, flag := range []string{
		rdbPVC,
		rdbPod,
		rdbDataPath,
		rdbContainer,
	} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}

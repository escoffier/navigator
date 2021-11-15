package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/cmd/proxy"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"net/url"
)

var (
	certFile       = ""
	keyFile        = ""
	targetHost     = ""
	clusterMgrAddr = ""
)

const clusterPath = "/internal/cluster"

func NewProxyCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {

			targetUrl := getTargetUrl(targetHost, clusterMgrAddr)
			if targetUrl == nil {
				logging.GetLogger().Error().Msg("no target url")
				return nil
			}
			server, err := proxy.NewProxyServer(targetUrl, certFile, keyFile)
			if err != nil {
				return err
			}

			err = server.Run()
			if err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&targetHost, "target-host", "", "set target url")
	cmd.Flags().StringVar(&clusterMgrAddr, "clusterMgrAddress", "http://cluster-manager:9443", "cluster manager address")
	cmd.Flags().StringVar(&certFile, "tlsCertPath", "/etc/webhook/certs/tls.crt", "The path of tls cert")
	cmd.Flags().StringVar(&keyFile, "tlsKeyPath", "/etc/webhook/certs/tls.key", "The path of tls key")
	return cmd
}

func getTargetUrl(host, clusterMgr string) *url.URL {
	targetUrl, err := url.Parse(host)
	if err != nil {
		return nil
	}

	clusterMgr = clusterMgr + clusterPath

	cluster := utils.GetClusterInfo(clusterMgr)

	if cluster == nil || cluster.Key == "" {
		return nil
	}
	logging.GetLogger().Info().Msgf("current cluster is: %s-%s", cluster.Name, cluster.Key)

	targetUrl.Scheme = "https"
	targetUrl.RawQuery = "cluster=" + cluster.Key
	targetUrl.Path = "/internal/webhook"
	return targetUrl
}

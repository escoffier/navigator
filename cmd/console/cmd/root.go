// Package cmd is for all the Cobra commands
package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "console",
	Short: "The centralized server",
	Long:  `The centralized server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			logging.SetVerbose()
		}

		logging.GetLogger().Info().
			Str("version", Version).
			Msg("starting Vegeta Console")

		httpOpts := flag.GetHTTPOpts(cmd)
		logging.GetLogger().Info().
			Str("listen", httpOpts.HTTPListen).
			Str("webhooklisten", httpOpts.HTTPWebHookListen).
			Msg("HTTP options")

		mongoOpts := flag.GetMongoOpts(cmd)
		logging.GetLogger().Info().
			Str("endpoint", mongoOpts.Endpoint).
			Str("username", mongoOpts.Username).
			Str("secretname", mongoOpts.SecretName).
			Str("database", mongoOpts.Database).
			Str("pvc", mongoOpts.PVC).
			Str("pod", mongoOpts.Pod).
			Str("dataPath", mongoOpts.DataPath).
			Msg("Mongo options")

		postgresOpts := flag.GetPostgresOpts(cmd)
		logging.GetLogger().Info().
			Str("postgres connection", postgresOpts.PostgresConnectionString).
			Str("pvc", postgresOpts.PVC).
			Str("pod", postgresOpts.Pod).
			Str("dataPath", postgresOpts.DataPath).
			Msg("Postgres options")

		emailOpts := flag.GetEmailOpts(cmd)
		logging.GetLogger().Info().
			Str("Email user", emailOpts.Username).
			Str("Email Host", emailOpts.Host).
			Str("Email Port", emailOpts.Port).
			Str("Email Suffix", emailOpts.Suffix).
			Bool("Email Check", emailOpts.Check).
			Msg("Vegeta Email options")

		scannerOpts := flag.GetVegetaScannerOpts(cmd)
		logging.GetLogger().Info().
			Str("host", scannerOpts.Host).
			Int("port", scannerOpts.Port).
			Msg("Vegeta Scanner options")

		scapOpts := flag.GetScapOpts(cmd)
		logging.GetLogger().Info().
			Str("scap-job-repo", scapOpts.HostPort).
			Str("scap-job-tag", scapOpts.ImageTag).
			Int32("policy-counts", scapOpts.PolicyCounts).
			Msg("Scap options")

		redisOpts := flag.GetRedisOpts(cmd)
		logging.GetLogger().Info().
			Str("endpoint", redisOpts.Endpoint).
			Msg("Redis options")

		harborOpts := flag.GetHarborOpts(cmd)
		logging.GetLogger().Info().
			Str("harbor-url", harborOpts.URL).
			Str("harbor-username", harborOpts.Username).
			Str("harbor-password", "***").
			Bool("harbor-skiptlsverify", harborOpts.SkipTLSVerify).
			Msg("Harbor REST client options")

		elasticOpts := flag.GetElasticOpts(cmd)
		logging.GetLogger().Info().
			Str("host", elasticOpts.Host).
			Str("port", elasticOpts.Port).
			Str("index", elasticOpts.Index).
			Str("username", elasticOpts.Username).
			Msg("Elastic options")

		secProfilesOpts := flag.GetSecProfilesOpts(cmd)
		logging.GetLogger().Info().
			Str("host", secProfilesOpts.Host).
			Int("port", secProfilesOpts.Port).
			Msg("Security Profiles options")

		microsegOpts := flag.GetMicrosegOpts(cmd)
		logging.GetLogger().Info().
			Str("host", microsegOpts.Host).
			Int("port", microsegOpts.Port).
			Msg("microsegmentation options")

		webhookOpts := flag.GetWebHookOpts(cmd)
		logging.GetLogger().Info().
			Str("host", webhookOpts.Host).
			Int("port", webhookOpts.Port).
			Msg("webhook options")

		console, err := service.NewConsole(httpOpts, mongoOpts, postgresOpts, scannerOpts, scapOpts, redisOpts, elasticOpts, harborOpts, emailOpts, secProfilesOpts, microsegOpts, webhookOpts)

		if err != nil {
			return err
		}

		lifecycle.NewApplication(
			console,
		).Run()

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to startup")
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")

	flag.AddHTTPFlags(rootCmd)
	flag.AddMongoFlags(rootCmd)
	flag.AddPostgresFlags(rootCmd)
	flag.AddVegetaScannerFlags(rootCmd)
	flag.AddScapFlags(rootCmd)
	flag.AddRedisFlags(rootCmd)
	flag.AddElasticFlags(rootCmd)
	flag.AddHarborFlags(rootCmd)
	flag.AddEmailOpts(rootCmd)
	flag.AddSecProfilesOpts(rootCmd)
	flag.AddMicrosegmentationFlags(rootCmd)
	flag.AddWebHookFlags(rootCmd)

	flag.ConfigViper()
}

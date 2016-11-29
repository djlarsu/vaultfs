// Copyright © 2016 Asteris, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd controls global settings
var RootCmd = &cobra.Command{
	Use:   "vaultfs",
	Short: "use Docker's volumes to mount Vault secrets",
	Long:  `Mount a vault server as a FUSE filesystem.

Client configuration is accomplished using the normal Vault environment variables:

VAULT_ADDR	The address of the Vault server expressed as a URL and port,
			for example: http://127.0.0.1:8200
VAULT_CACERT	Path to a PEM-encoded CA cert file to use to verify the
				Vault server SSL certificate.
VAULT_CAPATH	Path to a directory of PEM-encoded CA cert files to verify
				the Vault server SSL certificate. If VAULT_CACERT is specified,
				its value will take precedence.
VAULT_CLIENT_CERT	Path to a PEM-encoded client certificate for TLS authentication
					to the Vault server.
VAULT_CLIENT_KEY	Path to an unencrypted PEM-encoded private key matching the client
					certificate.
VAULT_MAX_RETRIES	The maximum number of retries when a 5xx error code is encountered.
					Default is 2, for three total tries; set to 0 or less to disable retrying.
VAULT_SKIP_VERIFY	If set, do not verify Vault's presented certificate before communicating
					with it. Setting this variable is not recommended except during testing.
VAULT_TLS_SERVER_NAME	If set, use the given name as the SNI host when connecting via TLS.
`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		logrus.WithError(err).Error("error executing command")
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig, initLogging, lockMemory)

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default /etc/vaultfs)")

	// logging flags
	RootCmd.PersistentFlags().String("log-level", "info", "log level (one of fatal, error, warn, info, or debug)")
	RootCmd.PersistentFlags().String("log-format", "text", "log level (one of text or json)")
	RootCmd.PersistentFlags().String("log-destination", "stdout:", "log destination (file:/your/output, stdout:, journald:, or syslog://tag@host:port#protocol)")

	RootCmd.PersistentFlags().StringP("token", "t", "", "The Vault Server token")

	if err := viper.BindPFlags(RootCmd.PersistentFlags()); err != nil {
		logrus.WithError(err).Fatal("could not bind flags")
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName("vaultfs")        // name of config file (without extension)
	viper.AddConfigPath("/etc/vaultfs") // adding sysconfig as the first search path
	viper.AddConfigPath("$HOME")          // home directory as another path
	viper.AutomaticEnv()                  // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logrus.WithField("config", viper.ConfigFileUsed()).Info("using config file from disk")
	}
}

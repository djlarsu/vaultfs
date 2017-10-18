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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	log "github.com/wrouesnel/go.log"
)

var cfgFile string

// RootCmd controls global settings
var RootCmd = &cobra.Command{
	Use:   "vaultfs",
	Short: "Mount a vault server as a FUSE filesystem.",
	Long:  `Mount a vault server as a FUSE filesystem.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// Output the version initially to logging.
	log.Infoln("Name:", Name, "Version:", Version)

	if err := RootCmd.Execute(); err != nil {
		log.WithError(err).Error("error executing command")
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig, initLogging, lockMemory)

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default /etc/vaultfs)")

	// logging flags
	RootCmd.PersistentFlags().String("log-level", "info", "log level (one of fatal, error, warn, info, or debug)")
	RootCmd.PersistentFlags().String("log-format", "stderr:", "log format. Defaults to stderr:. Example: logger:syslog?appname=bob&local=7 or logger:stdout?json=true.")

	RootCmd.PersistentFlags().String("auth-method", "", "authentication method to use if no token provided (supported: cert,ldap,approle)")
	RootCmd.PersistentFlags().String("auth-user", "", "username to use for the specified authentication method (if supported)")
	RootCmd.PersistentFlags().String("auth-role", "", "approle to use for the specified authentication method (if supported)")
	RootCmd.PersistentFlags().String("auth-secret", "", "password or secret to use for an authentication method (if supported by auth-method)")
	RootCmd.PersistentFlags().StringP("token", "t", "", "The Vault Server token (optional if using certificate auth)")

	if err := viper.BindPFlags(RootCmd.PersistentFlags()); err != nil {
		log.WithError(err).Fatal("could not bind flags")
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName("vaultfs")      // name of config file (without extension)
	viper.AddConfigPath("/etc/vaultfs") // adding sysconfig as the first search path
	viper.AddConfigPath("$HOME")        // home directory as another path
	viper.AutomaticEnv()                // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.WithField("config", viper.ConfigFileUsed()).Info("using config file from disk")
	}
}

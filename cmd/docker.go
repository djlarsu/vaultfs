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
	"errors"

	log "github.com/wrouesnel/go.log"
	"github.com/wrouesnel/vaultfs/docker"
	"github.com/docker/go-plugins-helpers/volume"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// dockerCmd represents the docker command
var dockerCmd = &cobra.Command{
	Use:   "docker {mountpoint}",
	Short: "start the docker volume server at the specified root",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("expected exactly one argument, a mountpoint")
		}

		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.WithError(err).Fatal("could not bind flags")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		vaultConfig := api.DefaultConfig()
		if err := vaultConfig.ReadEnvironment(); err != nil {
			log.Fatalln("Error reading vault environment keys:", err)
		}

		driver := docker.New(docker.Config{
			Root:       args[0],
			Token:      viper.GetString("token"),
			AuthMethod: viper.GetString("auth-method"),
			Vault:      vaultConfig,
		})

		log.WithFields(log.Fields{
			"root":     args[0],
			"address":  viper.GetString("address"),
			"insecure": viper.GetBool("insecure"),
			"socket":   viper.GetString("socket"),
		}).Info("starting plugin server")

		defer func() {
			for _, err := range driver.Stop() {
				log.WithError(err).Error("error stopping driver")
			}
		}()

		handler := volume.NewHandler(driver)
		log.WithField("socket", viper.GetString("socket")).Info("serving unix socket")
		err := handler.ServeUnix(viper.GetString("socket"), 0)
		if err != nil {
			log.WithError(err).Fatal("failed serving")
		}
	},
}

func init() {
	RootCmd.AddCommand(dockerCmd)

	dockerCmd.Flags().StringP("address", "a", "https://localhost:8200", "vault address")
	dockerCmd.Flags().BoolP("insecure", "i", false, "skip SSL certificate verification")
	dockerCmd.Flags().StringP("token", "t", "", "vault token")
	dockerCmd.Flags().StringP("socket", "s", "/run/docker/plugins/vault.sock", "socket address to communicate with docker")
}

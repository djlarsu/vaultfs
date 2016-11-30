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
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/asteris-llc/vaultfs/fs"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// mountCmd represents the mount command
var mountCmd = &cobra.Command{
	Use:   "mount {mountpoint}",
	Short: "mount a vault FS at the specified mountpoint",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("expected exactly one argument")
		}

		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.WithError(err).Fatal("could not bind flags")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Read vault config from environment
		vaultConfig := api.DefaultConfig()
		if err := vaultConfig.ReadEnvironment(); err != nil {
			log.Fatalln("Error reading vault environment keys:", err)
		}

		log.Info("Creating FUSE client for Vault server")

		fs, err := fs.New(vaultConfig, args[0], viper.GetString("root"),
			viper.GetString("token"), viper.GetString("auth-method"))
		if err != nil {
			log.WithError(err).Fatal("error creatinging fs")
		}

		// handle interrupt
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

			<-c
			log.Info("stopping")
			err := fs.Unmount()
			if err != nil {
				log.WithError(err).Fatal("could not unmount cleanly")
			}
		}()

		err = fs.Mount()
		if err != nil {
			log.WithError(err).Fatal("could not continue")
		}
	},
}

func init() {
	RootCmd.AddCommand(mountCmd)
	mountCmd.Flags().StringP("root", "r", "secret", "list of root paths to mount")
}

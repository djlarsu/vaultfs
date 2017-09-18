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

package fs

import (
	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/api"
	"github.com/wrouesnel/go.log"

	"github.com/wrouesnel/vaultfs/vaultapi"
	"gopkg.in/AlecAivazis/survey.v1"
)

// VaultFS is a vault filesystem.
// It also wraps the accessor functions needed by the filesystem nodes to
// manage access to backend keys in vault (i.e. error handling, failover and
// re-auth attempts.
type VaultFS struct {
	logical    vaultapi.Logical
	root       string
	conn       *fuse.Conn
	mountpoint string
	logger     log.Logger // Context aware logger
}

// New returns a new VaultFS
func New(config *api.Config, mountpoint string, root string, token string, authMethod string, authUser string, authSecret string) (*VaultFS, error) {
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	// Prompt for a password if none is specified.
	if authMethod == "ldap" {
		if authSecret == "" {
			passwordQuery := &survey.Password{
				Message: "Enter Password (will be hidden):",
			}
			if err := survey.AskOne(passwordQuery, &authSecret ,nil) ; err != nil {
				return nil, err
			}
		}
	}

	// preAuthBackend is used to authenticate
	preAuthBackend := vaultapi.NewVaultLogicalBackend(client, token, authMethod, authUser, authSecret)

	if err := preAuthBackend.Auth(); err != nil {
		return nil, err
	}

	return &VaultFS{
		logical:    preAuthBackend,
		root:       root,
		mountpoint: mountpoint,
		logger:     log.WithField("address", config.Address),
	}, nil
}

func (v *VaultFS) log() log.Logger {
	return log.WithFields(log.Fields{
		"vault_root": v.root,
		"mountpoint": v.mountpoint,
	})
}

// logic provides wrapped access to the Vault api.Logical backend.
// It manages automatically re-authing sessions.
func (v *VaultFS) logic() vaultapi.Logical {
	return v.logical
}

// Mount the FS at the given mountpoint
func (v *VaultFS) Mount() error {
	var err error
	v.conn, err = fuse.Mount(
		v.mountpoint,
		fuse.FSName("vault"),
		fuse.VolumeName("vault"),
	)

	v.log().Debug("created conn")
	if err != nil {
		return err
	}

	log.Debug("starting to serve")
	return fs.Serve(v.conn, v)
}

// Unmount the FS
func (v *VaultFS) Unmount() error {
	if v.conn == nil {
		return errors.New("not mounted")
	}

	err := fuse.Unmount(v.mountpoint)
	if err != nil {
		return err
	}

	err = v.conn.Close()
	if err != nil {
		return err
	}

	v.logger.Debug("closed connection, waiting for ready")
	<-v.conn.Ready
	if v.conn.MountError != nil {
		return v.conn.MountError
	}

	return nil
}

// Root returns the struct that does the actual work
func (v *VaultFS) Root() (fs.Node, error) {
	v.logger.Debug("returning root")
	return NewSecretDir(v, v.root)
}

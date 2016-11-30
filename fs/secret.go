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
	"fmt"
	"os"
	"strings"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

// Statically ensure that *Secret implements the given interface
var _ = fs.HandleReadDirAller(&SecretDir{})
var _ = fs.NodeStringLookuper(&SecretDir{})

// Static map of directory items found under a secret
var secretDirEntrys = map[string]fuse.Dirent{
	"lease_id": fuse.Dirent{
		Name:  "lease_id",
		Inode: 0,
		Type:  fuse.DT_File,
	},
	// LeaseDuration
	"lease_duration": fuse.Dirent{
		Name:  "lease_duration",
		Inode: 0,
		Type:  fuse.DT_File,
	},
	// "Renewable" file is always empty
	"renewable": fuse.Dirent{
		Name:  "renewable",
		Inode: 0,
		Type:  fuse.DT_File,
	},
	// Data is a directory
	"data": fuse.Dirent{
		Name:  "data",
		Inode: 0,
		Type:  fuse.DT_Dir,
	},
	// Warnings is a file.
	"warnings": fuse.Dirent{
		Name:  "warnings",
		Inode: 0,
		Type:  fuse.DT_File,
	},
	// Auth is a directory
	"auth": fuse.Dirent{
		Name:  "auth",
		Inode: 0,
		Type:  fuse.DT_Dir,
	},
	// WrapInfo is a directory
	"wrap_info": fuse.Dirent{
		Name:  "wrap_info",
		Inode: 0,
		Type:  fuse.DT_Dir,
	},
}

// Secret represents secrets which directly contain data (cannot be treated as
// directories in the vault backend). They are still treated as directories in
// FUSE because we want to expose data/ as files.
type Secret struct {
	*api.Secret
	logic      *api.Logical
	lookupPath string
}

// NewSecret creates a node which represents a directory and provides access to
// the subkeys of a secret.
func NewSecret(logic *api.Logical, backend *api.Secret, lookupPath string) (*Secret, error) {
	if lookupPath == "" {
		return nil, errors.Errorf("secret root must have non-zero length path")
	}
	if logic == nil {
		return nil, errors.Errorf("nil logic connection not allowed")
	}
	if backend == nil {
		return nil, errors.Errorf("nil backend not allowed")
	}

	return &Secret{
		Secret:     backend,
		logic:      logic,
		lookupPath: lookupPath,
	}, nil
}

// Attr returns attributes about this Secret
func (s Secret) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = os.ModeDir | os.FileMode(0555)
	a.Uid = 0
	a.Gid = 0

	return nil
}

// Lookup looks up a path
func (s *Secret) Lookup(ctx context.Context, name string) (fs.Node, error) {
	log := log.WithField("root", s.lookupPath).WithField("name", name)
	log.Debugln("Handling Secret.Lookup")
	// Lookup which node in the fixed list...
	dir, found := secretDirEntrys[name]
	if !found {
		log.Debugln("Secret.Lookup not valid for Secret.")
		return nil, fuse.ENOENT
	}

	// Return a value node if a file, else one of the specialized directories
	switch dir.Name {
	case "lease_id":
		return NewValue(s.LeaseID)
	case "lease_duration":
		return NewValue(fmt.Sprintf("%v", s.LeaseDuration))
	case "renewable":
		return NewValue(fmt.Sprintf("%v", s.Renewable))
	case "warnings":
		return NewValue(strings.Join(s.Warnings, "\n"))
	case "data":
		subdir := make(map[string]interface{})
		for filename, data := range s.Data {
			if value, ok := data.(string); !ok {
				log.WithField("name", name).
					WithField("childname", filename).
					Errorf("Not a string in backend - ignoring: %T", data)
			} else {
				subdir[filename] = value
			}
		}
		return NewStaticDir(subdir)
	case "auth":
		if s.Auth == nil {
			return NewStaticDir(nil)
		}

		authDir := make(map[string]interface{})
		authDir["client_token"] = s.Auth.ClientToken
		authDir["accessor"] = s.Auth.Accessor
		authDir["policies"] = strings.Join(s.Auth.Policies, "\n")

		metadata := make(map[string]interface{})
		for k, v := range s.Auth.Metadata {
			metadata[k] = v
		}
		authDir["metadata"] = metadata
		authDir["lease_duration"] = fmt.Sprintf("%v", s.Auth.LeaseDuration)
		authDir["renewable"] = fmt.Sprintf("%v", s.Auth.Renewable)

		return NewStaticDir(authDir)
	case "wrap_info":
		if s.WrapInfo == nil {
			return NewStaticDir(nil)
		}

		wrapInfo := make(map[string]interface{})
		wrapInfo["token"] = s.WrapInfo.Token
		wrapInfo["ttl"] = fmt.Sprintf("%v", s.WrapInfo.TTL)
		wrapInfo["creation_time"] = s.WrapInfo.CreationTime.String()
		wrapInfo["wrapped_accessor"] = s.WrapInfo.WrappedAccessor

		return NewStaticDir(wrapInfo)
	}

	return nil, fuse.ENOENT
}

// ReadDirAll returns a list of the subkey-files available for a secret
func (s *Secret) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	log.WithField("path", s.lookupPath).Debugln("handling Secret.ReadDirAll call")
	dirs := []fuse.Dirent{}

	for _, v := range secretDirEntrys {
		dirs = append(dirs, v)
	}

	return dirs, nil
}

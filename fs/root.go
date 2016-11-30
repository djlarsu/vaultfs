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
	"os"
	"path"
	"strings"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	log "github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

// These lines statically ensure that a *SnapshotsDir implement the given
// interfaces; a misplaced refactoring of the implementation that breaks
// the interface will be catched by the compiler
var _ = fs.HandleReadDirAller(&Root{})
var _ = fs.NodeStringLookuper(&Root{})

//var table = crc64.MakeTable(crc64.ISO)

// Root implements both Node and Handle
type Root struct {
	lookupPath string
	logic      *api.Logical
}

// NewRoot creates a new root and returns it
func NewRoot(root string, logic *api.Logical) *Root {
	log.WithField("root", root).Infoln("Creating new vault root.")
	return &Root{
		lookupPath: root,
		logic:      logic,
	}
}

// Attr sets attrs on the given fuse.Attr
func (Root) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = os.ModeDir | os.FileMode(0555)
	a.Uid = 0
	a.Gid = 0

	return nil
}

// Lookup looks up a path
func (r *Root) Lookup(ctx context.Context, name string) (fs.Node, error) {
	log := log.WithField("name", name)
	log.Debugln("Handling Root.Lookup")

	lookupPath := path.Join(r.lookupPath, name)

	// TODO: handle context cancellation
	secret, err := r.logic.Read(lookupPath)
	if err != nil {
		// Was this just permission denied (in which case fall through to directory listing)
		// Note: the error handling in the vault client library *sucks*
		if strings.Contains(err.Error(), "Code: 403") {
			log.WithError(err).WithField("root", r.lookupPath).Error("Permission denied as literal secret")
		} else {
			// Connection level errors won't recover further down.
			log.WithError(err).WithField("root", r.lookupPath).Error("Error reading key")
			return nil, fuse.EIO
		}
	}

	// Literal secret
	if secret != nil {
		log.Debugln("Lookup succeeded for file-like secret.")
		return NewSecret(r.logic, secret, lookupPath)
	}

	// Not a literal secret (or permission denied). Try listing to see if it's a directory.
	dirSecret, err := r.logic.List(lookupPath)
	if err != nil {
		if strings.Contains(err.Error(), "Code: 403") {
			log.WithError(err).WithField("root", r.lookupPath).Info("Permission denied - returning empty directory to allow traversal.")
			return NewSecretDir(r.logic, dirSecret, lookupPath, false)
		} else {
			// Connection level errors won't recover further down.
			log.WithError(err).WithField("root", r.lookupPath).Error("Error reading key")
			return nil, fuse.EIO
		}
	}

	if dirSecret != nil {
		log.Debugln("Lookup succeeded for directory-like secret.")
		return NewSecretDir(r.logic, dirSecret, lookupPath, true)
	}

	log.Debugln("Lookup failed.")
	return nil, fuse.ENOENT
}

// ReadDirAll returns a list of secrets
func (r *Root) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	log.WithField("path", r.lookupPath).Debugln("handling Root.ReadDirAll call")

	lookupPath := path.Join(r.lookupPath)
	s, err := r.logic.List(lookupPath)
	if err != nil {
		if strings.Contains(err.Error(), "Code: 403") {
			log.WithError(err).WithField("root", r.lookupPath).Info("Permission denied - returning empty directory to allow traversal.")
			return []fuse.Dirent{}, nil
		} else {
			// Connection level errors won't recover further down.
			log.WithError(err).WithField("root", r.lookupPath).Error("Error reading key")
			return nil, fuse.EIO
		}
	}

	if s.Data == nil {
		return []fuse.Dirent{}, nil
	}

	keys, found := s.Data["keys"]
	if !found {
		log.Error("Directory-like secret had no \"keys\" field.")
		return []fuse.Dirent{}, nil
	}

	if keys == nil {
		return []fuse.Dirent{}, nil
	}

	keylist, ok := keys.([]interface{})
	if !ok {
		log.Error("Directory-like secret keys field was not a list.")
		return []fuse.Dirent{}, nil
	}

	dirs := []fuse.Dirent{}
	for _, value := range keylist {
		// Ensure we don't have a trailing /
		rawName, ok := value.(string)
		if !ok {
			log.Error("Value from backend for directory-like secret was not a string!")
		}
		secretName := strings.TrimRight(rawName, "/")

		d := fuse.Dirent{
			Name:  secretName,
			Inode: 0,
			Type:  fuse.DT_Dir,
		}
		dirs = append(dirs, d)
	}

	return dirs, nil
}

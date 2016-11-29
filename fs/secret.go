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

	"bazil.org/fuse"
	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
	"bazil.org/fuse/fs"
)

// Statically ensure that *Secret implements the given interface
var _ = fs.HandleReadDirAller(&SecretDir{})
var _ = fs.NodeStringLookuper(&SecretDir{})

// Static map of directory items found under a secret
var secretDirEntrys = map[string]fuse.Dirent{
	"lease_id" : fuse.Dirent{
		Name: "lease_id",
		//Inode: 1, //crc64.Checksum([]byte(s.lookupPath), table)
		Type: fuse.DT_File,
	},

	// LeaseDuration
	"lease_duration" : fuse.Dirent{
		Name: "lease_duration",
		//Inode: 1, //crc64.Checksum([]byte(s.lookupPath), table)
		Type: fuse.DT_File,
	},

	// "Renewable" file is always empty
	"renewable" : fuse.Dirent{
		Name: "renewable",
		//Inode: 1, //crc64.Checksum([]byte(s.lookupPath), table)
		Type: fuse.DT_File,
	},

	// Data is a directory
	"data" : fuse.Dirent{
		Name: "data",
		//Inode: 1, //crc64.Checksum([]byte(s.lookupPath), table)
		Type: fuse.DT_Dir,
	},

	// Warnings is a file.
	"warnings" : fuse.Dirent{
		Name: "warnings",
		//Inode: 1, //crc64.Checksum([]byte(s.lookupPath), table)
		Type: fuse.DT_File,
	},

	// Auth is a directory
	"auth" : fuse.Dirent{
		Name: "auth",
		//Inode: 1, //crc64.Checksum([]byte(s.lookupPath), table)
		Type: fuse.DT_Dir,
	},

	// WrapInfo is a directory
	"wrap_info" : fuse.Dirent{
		Name: "wrap_info",
		//Inode: 1, //crc64.Checksum([]byte(s.lookupPath), table)
		Type: fuse.DT_Dir,
	},
}

// Secret's represent secrets which directly contain data (cannot be treated as directories in the vault backend).
// They are still treated as directories in FUSE because we want to expose data/ as files.
type Secret struct {
	*api.Secret
	logic *api.Logical
	inode uint64
	lookupPath string
}

func (s Secret) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	return nil
}

// Attr returns attributes about this Secret
func (s Secret) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = s.inode
	a.Mode = os.ModeDir | 0555
	return nil
}

//func (s Secret) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
//	data, err := s.ReadAll(ctx)
//	if err == io.ErrUnexpectedEOF || err == io.EOF {
//		err = nil
//	}
//	resp.Data = data[:len(data)]
//	return err
//}

// Lookup looks up a path
func (s *Secret) Lookup(ctx context.Context, name string) (fs.Node, error) {
	// Lookup which node in the fixed list...
	dir, found := secretDirEntrys[name]
	if !found {
		return nil, fuse.ENOENT
	}

	// Return a value node if a file, else one of the specialized directories
	if dir.Type == fuse.DT_File {
		switch dir.Name {
		case "lease_id":
			return NewValue(s.LeaseID)
		case "lease_duration" :
			return NewValue(s.LeaseDuration)
		case "renewable" :
			return NewValue(s.Renewable)
		case "data" :
			break
		case "warnings" :
			return NewValue(s.Warnings)
		case "auth" :
		case "wrap_info" :
		}
	}

	return nil, fuse.ENOENT
}

// ReadDirAll returns a list of the subkey-files available for a secret
func (s *Secret) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	logrus.WithField("path", s.lookupPath).Debugln("handling Root.ReadDirAll call")

	if s.Data["keys"] == nil {
		return []fuse.Dirent{}, nil
	}

	dirs := []fuse.Dirent{}

	for _, v := range secretDirEntrys {
		//v.Inode = crc64.Checksum([]byte(s.lookupPath), table)
		dirs = append(dirs, v)
	}

	logrus.Debugln("ReadDirAll succeeded.", dirs)
	return dirs, nil
}
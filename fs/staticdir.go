// A static directory exposes a tree of fixed values into a
// hierarchy which doesn't change.

package fs

import (
	"os"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/go-errors/errors"
	log "github.com/wrouesnel/go.log"
	"golang.org/x/net/context"
)

// Statically ensure that *SecretDir implement those interface
var _ = fs.HandleReadDirAller(&SecretDir{})
var _ = fs.NodeStringLookuper(&SecretDir{})

// StaticDir implements a fuse directory structure with static content.
type StaticDir struct {
	children map[string]fs.Node // Static children of this node
}

// NewStaticDir generates a new static directory tree of arbitrary depth from
// the supplied map.
func NewStaticDir(values map[string]interface{}) (*StaticDir, error) {
	// Validate the provided subdirectory tree (only allowed types are strings
	// and more maps.
	newDir := &StaticDir{
		children: make(map[string]fs.Node),
	}

	// If nil map, return an empty directory.
	if values == nil {
		return newDir, nil
	}

	for filename, content := range values {
		// Check no name collisions
		_, found := newDir.children[filename]
		if found {
			return nil, errors.Errorf("filename collision when generating tree: %v", filename)
		}
		// Recurse and build the tree
		switch v := content.(type) {
		case string:
			subfile, err := NewValue(v)
			if err != nil {
				return nil, errors.WrapPrefix(err, "error generating subdirectory tree: %v", 0)
			}
			newDir.children[filename] = subfile
		case map[string]interface{}:
			subDir, err := NewStaticDir(v)
			if err != nil {
				return nil, errors.WrapPrefix(err, "error generating subdirectory tree: %v", 0)
			}
			newDir.children[filename] = subDir
		default:
			return nil, errors.Errorf("invalid type for static directory: %v", v)
		}
	}

	return newDir, nil
}

// Attr sets attrs on the given fuse.Attr
func (s *StaticDir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = os.ModeDir | os.FileMode(0555)
	a.Uid = 0
	a.Gid = 0

	return nil
}

// Lookup looks up a path
func (s *StaticDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	log := log.WithField("name", name)
	log.Debugln("handling StaticDir.Lookup")

	// Lookup which node in the static list
	dir, found := s.children[name]
	if !found {
		return nil, fuse.ENOENT
	}
	return dir, nil
}

// ReadDirAll enumerates the static content as files if a StaticValue or
// direcotries if another StaticDir.
func (s *StaticDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	log.Debugln("handling StaticDir.ReadDirAll call")

	dirs := []fuse.Dirent{}

	for k, v := range s.children {
		switch v.(type) {
		case *StaticDir:
			dirs = append(dirs, fuse.Dirent{
				Name: k,
				Type: fuse.DT_Dir,
			})
		case *StaticValue:
			dirs = append(dirs, fuse.Dirent{
				Name: k,
				Type: fuse.DT_File,
			})
		default:
			log.Errorln("Unknown filetype in static directory structure!")
		}
	}

	return dirs, nil
}

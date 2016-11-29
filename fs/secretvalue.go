// A file which exposes a value read from a secret in vault.

package fs

import (
	"os"

	"bazil.org/fuse"
	"github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
	"bazil.org/fuse/fs"
"errors"
)

// Statically ensure that *file implements the given interface
var _ = fs.HandleReader(&Value{})
var _ = fs.HandleReleaser(&Value{})

type Value struct {
	value string
}

// Returns a new Value node (a file with static content)
func NewValue(value string) (*Value, error) {
	return &Value{
		value: value,
	}
}

// Attr sets attrs on the given fuse.Attr
func (f *Value) Attr(ctx context.Context, a *fuse.Attr) error {
	logrus.Debug("handling Root.Attr call")
	a.Inode = 0
	a.Mode = os.FileMode(0444)
	a.Uid = 0
	a.Gid = 0

	return nil
}


func (f *Value) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	if uint64(req.Offset) > len(f.value) {
		return errors.New("offset greater than files size")
	}

	// handle special case: file is empty
	if len(f.value) == 0 {
		resp.Data = resp.Data[:0]
		return nil
	}

	copied := copy(resp.Data, []byte(f.value))
	resp.Data = resp.Data[:copied]

	return nil
}

// Nothing to release
func (f *Value) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	return nil
}
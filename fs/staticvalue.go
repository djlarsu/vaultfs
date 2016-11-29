// A file which only ever serves a static value.

package fs

import (
	"os"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/go-errors/errors"
	"golang.org/x/net/context"
)

// Statically ensure that *file implements the given interface
var _ = fs.HandleReader(&StaticValue{})

// StaticValue implements a node which always serves the same bytes.
type StaticValue struct {
	value []byte
}

// NewValue returns a new Value node (a file with static content)
func NewValue(value string) (*StaticValue, error) {
	return &StaticValue{
		value: []byte(value),
	}, nil
}

// Attr sets attrs on the given fuse.Attr
func (f *StaticValue) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = os.FileMode(0440)
	a.Uid = 0
	a.Gid = 0
	a.Size = uint64(len(f.value))

	return nil
}

// Read simply returns the statically stored content of the node.
func (f *StaticValue) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	if uint64(req.Offset) > uint64(len(f.value)) {
		return errors.New("offset greater than file size")
	}

	// File empty.
	if len(f.value) == 0 {
		resp.Data = resp.Data[:0]
		return nil
	}

	// Just copy the part of the value we wanted and return it.
	dst := resp.Data[0:req.Size]
	copiedBytes := copy(dst, f.value[req.Offset:])
	resp.Data = resp.Data[:copiedBytes]
	return nil
}

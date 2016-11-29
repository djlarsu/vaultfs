package fs

import (
	"os"
	"path"
	"strings"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

// Statically ensure that *SecretDir implement those interface
var _ = fs.HandleReadDirAller(&SecretDir{})
var _ = fs.NodeStringLookuper(&SecretDir{})

// SecretDir implements Node and Handle
// This is the type we return if the Secret is a secret that we only were able to get via a list - i.e. is directory-like.
type SecretDir struct {
	*api.Secret
	logic      *api.Logical
	lookupPath string // Vault Path used to find this key.
}

// NewSecretDir creates a SecretDir node linked to the given secret and vault API.
func NewSecretDir(logic *api.Logical, backend *api.Secret, lookupPath string) (*SecretDir, error) {
	if lookupPath == "" {
		return nil, errors.Errorf("secret root must have non-zero length path")
	}
	if logic == nil {
		return nil, errors.Errorf("nil logic connection not allowed")
	}
	if backend == nil {
		return nil, errors.Errorf("nil backend not allowed")
	}

	return &SecretDir{
		Secret:     backend,
		logic:      logic,
		lookupPath: lookupPath,
	}, nil
}

// Attr returns attributes about this Secret
func (s SecretDir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = os.ModeDir | os.FileMode(0555)
	a.Uid = 0
	a.Gid = 0

	return nil
}

// Lookup looks up a path
func (s *SecretDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	log := log.WithField("root", s.lookupPath).WithField("name", name)
	log.Debugln("Handling SecretDir.Lookup")

	lookupPath := path.Join(s.lookupPath, name)

	// TODO: handle context cancellation
	secret, err := s.logic.Read(lookupPath)
	if err != nil {
		log.WithError(err).WithField("root", s.lookupPath).Error("Error reading key")
		return nil, fuse.EIO
	}

	// Literal secret
	if secret != nil {
		log.Debugln("Lookup succeeded for file-like secret.")
		return NewSecret(s.logic, secret, lookupPath)
	}

	// Not a literal secret. Try listing to see if it's a directory.
	dirSecret, err := s.logic.List(lookupPath)
	if err != nil {
		log.WithError(err).WithField("root", s.lookupPath).Error("Error listing key")
		return nil, fuse.EIO
	}

	if secret != nil {
		log.Debugln("Lookup succeeded for directory-like secret.")
		return NewSecretDir(s.logic, dirSecret, lookupPath)
	}

	log.Debugln("Lookup failed.")
	return nil, fuse.ENOENT
}

// ReadDirAll returns a list of secrets in this directory
func (s *SecretDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	log.WithField("path", s.lookupPath).Debugln("handling SecretDir.ReadDirAll call")
	if s.Data["keys"] == nil {
		return []fuse.Dirent{}, nil
	}

	dirs := []fuse.Dirent{}
	for i := 0; i < len(s.Data["keys"].([]interface{})); i++ {
		// Ensure we don't have a trailing /
		rawName := s.Data["keys"].([]interface{})[i].(string)
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

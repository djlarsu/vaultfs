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
	logic       *api.Logical
	lookupPath  string // Vault Path used to find this key.
	isPopulated bool   // Was the vault path able to be resolved or are we a placeholder?
}

// NewSecretDir creates a SecretDir node linked to the given secret and vault API.
func NewSecretDir(logic *api.Logical, backend *api.Secret, lookupPath string, isPopulated bool) (*SecretDir, error) {
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
		Secret:      backend,
		logic:       logic,
		lookupPath:  lookupPath,
		isPopulated: isPopulated,
	}, nil
}

// Attr returns attributes about this Secret
func (s SecretDir) Attr(ctx context.Context, a *fuse.Attr) error {
	if !s.isPopulated {
		// Not populated should be made to look traversable only
		a.Mode = os.ModeDir | os.FileMode(0111)
	} else {
		// Populated is readable
		a.Mode = os.ModeDir | os.FileMode(0555)
	}

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
		// Was this just permission denied (in which case fall through to directory listing)
		// Note: the error handling in the vault client library *sucks*
		if strings.Contains(err.Error(), "Code: 403") {
			log.WithError(err).WithField("root", s.lookupPath).Error("Permission denied as literal secret")
		} else {
			// Connection level errors won't recover further down.
			log.WithError(err).WithField("root", s.lookupPath).Error("Error reading key")
			return nil, fuse.EIO
		}
	}

	// Literal secret
	if secret != nil {
		log.Debugln("Lookup succeeded for file-like secret.")
		return NewSecret(s.logic, secret, lookupPath)
	}

	// Not a literal secret (or permission denied). Try listing to see if it's a directory.
	dirSecret, err := s.logic.List(lookupPath)
	if err != nil {
		if strings.Contains(err.Error(), "Code: 403") {
			log.WithError(err).WithField("root", s.lookupPath).Info("Permission denied - eturning empty directory to allow traversal.")
			return NewSecretDir(s.logic, dirSecret, lookupPath, false)
		} else {
			// Connection level errors won't recover further down.
			log.WithError(err).WithField("root", s.lookupPath).Error("Error reading key")
			return nil, fuse.EIO
		}
	}

	if dirSecret != nil {
		log.Debugln("Lookup succeeded for directory-like secret.")
		return NewSecretDir(s.logic, dirSecret, lookupPath, true)
	}

	log.Debugln("Lookup failed.")
	return nil, fuse.ENOENT
}

// ReadDirAll returns a list of secrets in this directory
func (s *SecretDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	log := log.WithField("path", s.lookupPath)
	log.Debugln("handling SecretDir.ReadDirAll call")
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

	//for i := 0; i < len(s.Data["keys"].([]interface{})); i++ {
	//	// Ensure we don't have a trailing /
	//	rawName := s.Data["keys"].([]interface{})[i].(string)
	//	secretName := strings.TrimRight(rawName, "/")
	//
	//	d := fuse.Dirent{
	//		Name:  secretName,
	//		Inode: 0,
	//		Type:  fuse.DT_Dir,
	//	}
	//	dirs = append(dirs, d)
	//}
	return dirs, nil
}

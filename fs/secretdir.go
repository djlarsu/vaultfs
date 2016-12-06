// SecretDir is the node type for directory-like secrets. Directory like secrets
// returns "keys" in their data, and respond to the LIST request to Vault.

package fs

import (
	"fmt"
	"os"
	"path"
	"strings"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	log "github.com/Sirupsen/logrus"
	"github.com/asteris-llc/vaultfs/vaultapi"
	"github.com/go-errors/errors"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

// Statically ensure that *SecretDir implement those interface
var _ = fs.HandleReadDirAller(&SecretDir{})
var _ = fs.NodeStringLookuper(&SecretDir{})

// Static map of directory items found under a non-listable secret
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

// SecretType is returned from internal lookup functions to track
// possibly changing key types.
type SecretType int

const (
	// SecretTypeBackendError returned if a key is not accessible at all.
	SecretTypeBackendError SecretType = iota
	// SecretTypeInaccessible returned if a key is inaccessible, and should be
	// treated as an empty, traversable directory until found otherwise.
	SecretTypeInaccessible
	// SecretTypeNonExistent return if key is non-existent (i.e. deleted since
	// we got here)
	SecretTypeNonExistent
	// SecretTypeDirectory returned if a key is accessible and list'able and
	// should be directory like
	SecretTypeDirectory
	// SecretTypeSecret returned if a key is read'able, and should have
	// secret-like behavior
	SecretTypeSecret
)

// SecretDir implements Node and Handle
// This type is used for accessing all content in a VaultFS as everything maps to directory-like structures. Various
// lookups produce either a child SecretDir or a a StaticDir tree.
type SecretDir struct {
	fs         *VaultFS // root filesystem this node is associated with
	lookupPath string   // Vault Path used to find this key.
}

// NewSecretDir creates a SecretDir node linked to the given secret and vault API.
func NewSecretDir(fs *VaultFS, lookupPath string) (*SecretDir, error) {
	log := log.WithField("root", lookupPath)
	log.Debug("NewSecret")

	if lookupPath == "" {
		err := errors.New("secret root must have non-zero length path")
		log.Error(err)
		return nil, err
	}
	if fs == nil {
		err := errors.New("nil vaultfs connection not allowed")
		log.Error(err)
		return nil, err
	}

	return &SecretDir{
		fs:         fs,
		lookupPath: lookupPath,
	}, nil
}

func (s *SecretDir) log() *log.Entry {
	return log.WithField("root", s.lookupPath)
}

// Does a lookup for the given lookup path, determines the type of key it
// currently is, and returns the associated secret.
func (s *SecretDir) lookup(ctx context.Context, lookupPath string) (SecretType, *api.Secret) {
	log := s.log().WithField("path", lookupPath)
	log.Debug("Handling SecretDir.lookup")

	// TODO: handle context cancellation
	secret, err := s.fs.logic().Read(lookupPath)
	if err != nil {
		// Was this just permission denied (in which case fall through to directory listing)
		// Note: the error handling in the vault client library *sucks*
		if errwrap.ContainsType(err, new(vaultapi.ErrVaultInaccessible)) {
			// Connection level errors won't recover further down.
			s.log().WithError(err).Error("Backend inaccessible")
			return SecretTypeBackendError, nil
		}

		// Permission denied - continue to try listing (which might be allowed).
		log.WithError(err).Debug("Permission denied (secret)")
	}

	// Literal secret was found (not found still requires us to try list below)
	if secret != nil {
		log.Debugln("Lookup succeeded for file-like secret")
		return SecretTypeSecret, secret
	}

	// Not a secret (or permission denied). Try listing to see if directory-like.
	dirSecret, err := s.fs.logic().List(lookupPath)
	if err != nil {
		if errwrap.ContainsType(err, new(vaultapi.ErrVaultInaccessible)) {
			// Connection level errors won't recover further down.
			log.WithError(err).Error("Error reading key")
			return SecretTypeBackendError, nil
		}
		log.WithError(err).Info("Permission denied (directory)")
		return SecretTypeInaccessible, nil
	}

	if dirSecret != nil {
		log.Debugln("Lookup succeeded for directory-like secret")
		return SecretTypeDirectory, dirSecret
	}

	// Key was not found
	return SecretTypeNonExistent, nil
}

// Does a lookup for the static subkeys of a Secret-type secret.
func (s *SecretDir) lookupSecret(ctx context.Context, secret *api.Secret, name string) (fs.Node, error) {
	log := s.log().WithField("name", name)
	// Lookup which node in the fixed list...
	dir, found := secretDirEntrys[name]
	if !found {
		log.Debugln("SecretDir.lookupSecret not valid for Secret.")
		return nil, fuse.ENOENT
	}

	// Return a value node if a file, else one of the specialized directories
	switch dir.Name {
	case "lease_id":
		return NewValue(secret.LeaseID)
	case "lease_duration":
		return NewValue(fmt.Sprintf("%v", secret.LeaseDuration))
	case "renewable":
		return NewValue(fmt.Sprintf("%v", secret.Renewable))
	case "warnings":
		return NewValue(strings.Join(secret.Warnings, "\n"))
	case "data":
		subdir := make(map[string]interface{})
		for filename, data := range secret.Data {
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
		if secret.Auth == nil {
			return NewStaticDir(nil)
		}

		authDir := make(map[string]interface{})
		authDir["client_token"] = secret.Auth.ClientToken
		authDir["accessor"] = secret.Auth.Accessor
		authDir["policies"] = strings.Join(secret.Auth.Policies, "\n")

		metadata := make(map[string]interface{})
		for k, v := range secret.Auth.Metadata {
			metadata[k] = v
		}
		authDir["metadata"] = metadata
		authDir["lease_duration"] = fmt.Sprintf("%v", secret.Auth.LeaseDuration)
		authDir["renewable"] = fmt.Sprintf("%v", secret.Auth.Renewable)

		return NewStaticDir(authDir)
	case "wrap_info":
		if secret.WrapInfo == nil {
			return NewStaticDir(nil)
		}

		wrapInfo := make(map[string]interface{})
		wrapInfo["token"] = secret.WrapInfo.Token
		wrapInfo["ttl"] = fmt.Sprintf("%v", secret.WrapInfo.TTL)
		wrapInfo["creation_time"] = secret.WrapInfo.CreationTime.String()
		wrapInfo["wrapped_accessor"] = secret.WrapInfo.WrappedAccessor

		return NewStaticDir(wrapInfo)
	}

	return nil, fuse.ENOENT
}

// Attr returns attributes about this Secret
func (s *SecretDir) Attr(ctx context.Context, a *fuse.Attr) error {
	s.log().Debugln("Handling SecretDir.Attr")

	a.Uid = 0
	a.Gid = 0

	currentSecretType, _ := s.lookup(ctx, s.lookupPath)

	switch currentSecretType {
	case SecretTypeBackendError:
		return fuse.EIO
	case SecretTypeNonExistent:
		return fuse.ENOENT
	case SecretTypeInaccessible:
		a.Mode = os.ModeDir | os.FileMode(0111)
	case SecretTypeDirectory, SecretTypeSecret:
		a.Mode = os.ModeDir | os.FileMode(0555)
	default:
		log.Error("BUG: unknown secret type found.")
		return fuse.EIO
	}

	return nil
}

// Lookup looks up a path. Vault policies mean its non-obvious what will happen.
// In brief: a path we can't access due to permissions always returns an
// unpopulated secret dir, which allows traversing further down the tree.
// But, if we can access it, and confirm it doesn't exist, we return ENOENT
// instead.
func (s *SecretDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	log := s.log().WithField("name", name)
	log.Debugln("Handling SecretDir.Lookup")

	// Check what type of node we are at the moment
	childLookupPath := path.Join(s.lookupPath, name)
	currentSecretType, currentSecret := s.lookup(ctx, s.lookupPath)

	switch currentSecretType {
	case SecretTypeBackendError:
		return nil, fuse.EIO
	case SecretTypeNonExistent:
		return nil, fuse.ENOENT
	case SecretTypeInaccessible:
		// Inaccessible is just a directory we *assume* exists.
		return NewSecretDir(s.fs, childLookupPath)
	case SecretTypeDirectory:
		// Directory type - so do another lookup.
		childSecretType, _ := s.lookup(ctx, childLookupPath)
		switch childSecretType {
		case SecretTypeBackendError:
			return nil, fuse.EIO
		case SecretTypeNonExistent:
			return nil, fuse.ENOENT
		// Important: note that for *child* secrets here, SecretTypeSecret is
		// is treated exactly the same.
		case SecretTypeInaccessible, SecretTypeDirectory, SecretTypeSecret:
			// Inaccessible is just a directory we *assume* exists
			// so is exactly like a directory.
			return NewSecretDir(s.fs, childLookupPath)
		default:
			log.Error("BUG: unknown secret type found.")
			return nil, fuse.EIO
		}
	case SecretTypeSecret:
		// We are being a secret. Call out to secretLookup.
		return s.lookupSecret(ctx, currentSecret, name)
	default:
		log.Error("BUG: unknown secret type found.")
		return nil, fuse.EIO
	}
}

func (s *SecretDir) readDirAllDirSecret(ctx context.Context, secret *api.Secret) ([]fuse.Dirent, error) {
	// Nil secret == 404, so it wasn't found.
	if secret == nil {
		return []fuse.Dirent{}, fuse.ENOENT
	}

	// Secret has no data - return an empty directory.
	if secret.Data == nil {
		return []fuse.Dirent{}, nil
	}

	keys, found := secret.Data["keys"]
	if !found {
		s.log().Error("Directory-like secret had no \"keys\" field.")
		return []fuse.Dirent{}, nil
	}

	if keys == nil {
		return []fuse.Dirent{}, nil
	}

	keylist, ok := keys.([]interface{})
	if !ok {
		s.log().Error("Directory-like secret keys field was not a list.")
		return []fuse.Dirent{}, nil
	}

	dirs := []fuse.Dirent{}
	for _, value := range keylist {
		// Ensure we don't have a trailing /
		rawName, ok := value.(string)
		if !ok {
			s.log().Error("Value from backend for directory-like secret was not a string!")
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

func (s *SecretDir) readDirAllSecret(ctx context.Context, secret *api.Secret) ([]fuse.Dirent, error) {
	dirs := []fuse.Dirent{}

	for _, v := range secretDirEntrys {
		dirs = append(dirs, v)
	}

	return dirs, nil
}

// ReadDirAll returns a list of secrets in this directory
func (s *SecretDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	s.log().Debugln("handling SecretDir.ReadDirAll call")

	currentSecretType, secret := s.lookup(ctx, s.lookupPath)

	switch currentSecretType {
	case SecretTypeBackendError:
		return []fuse.Dirent{}, fuse.EIO
	case SecretTypeNonExistent:
		return []fuse.Dirent{}, fuse.ENOENT
	case SecretTypeInaccessible:
		return []fuse.Dirent{}, nil
	case SecretTypeDirectory:
		return s.readDirAllDirSecret(ctx, secret)
	case SecretTypeSecret:
		return s.readDirAllSecret(ctx, secret)
	default:
		log.Error("BUG: unknown secret type found.")
		return []fuse.Dirent{}, fuse.EIO
	}
}

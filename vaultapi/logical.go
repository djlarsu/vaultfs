package vaultapi

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"strings"
	"github.com/hashicorp/errwrap"
)

// ensure ErrAuth implements Wrapper at compile-time.
var _ = errwrap.Wrapper(&ErrAuth{})

// ErrAuth is returned when any sort of authentication failure is
// observed (i.e. bad token, no token, permission denied).
type ErrAuth struct {
	innerError error
}

// Error implements the error interface
func (err ErrAuth) Error() string {
	return "authentication error"
}

// WrappedErrors implmenets the hashicorp/errwrap interface
func (err ErrAuth) WrappedErrors() []error {
	return []error{err.innerError}
}

// ErrAuthFailed is returned when an attempt to authenticate
// fails directly.
type ErrAuthFailed struct {
	innerError error
}

// Error implements the error interface
func (err ErrAuthFailed) Error() string {
	return "authentication attempt failed"
}

// WrappedErrors implmenets the hashicorp/errwrap interface
func (err ErrAuthFailed) WrappedErrors() []error {
	return []error{err.innerError}
}

// ErrPermissionDenied is returned when code 403 (permission denied)
// is returned by Vault
type ErrPermissionDenied struct {
	innerError error
}

// Error implements the error interface
func (err ErrPermissionDenied) Error() string {
	return "permission denied"
}

// WrappedErrors implmenets the hashicorp/errwrap interface
func (err ErrPermissionDenied) WrappedErrors() []error {
	return []error{err.innerError}
}

// ErrMissingClientToken is returned when code 403 (permission denied)
// is returned by Vault
type ErrMissingClientToken struct {
	innerError error
}

// Error implements the error interface
func (err ErrMissingClientToken) Error() string {
	return "missing client token"
}

// WrappedErrors implmenets the hashicorp/errwrap interface
func (err ErrMissingClientToken) WrappedErrors() []error {
	return []error{err.innerError}
}

// ErrVaultInaccessible is returned when code 403 (permission denied)
// is returned by Vault
type ErrVaultInaccessible struct {
	innerError error
}

// Error implements the error interface
func (err ErrVaultInaccessible) Error() string {
	return "vault inaccessible"
}

// WrappedErrors implmenets the hashicorp/errwrap interface
func (err ErrVaultInaccessible) WrappedErrors() []error {
	return []error{err.innerError}
}

// Logical is used to perform logical backend operations on Vault.
type Logical interface {
	Read(path string) (*api.Secret, error)
	List(path string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
	Delete(path string) (*api.Secret, error)
	Unwrap(wrappingToken string) (*api.Secret, error)
}

// AuthableLogical provides a method to request Auth'ing explicitely
type AuthableLogical interface {
	Logical
	Auth() error
}

// Logical wrapper for the vault API logical construct so it can be
// reimplemented with additional handling logic.
type vaultBackend struct {
	client     *api.Client
	logical    *api.Logical
	token      string
	authMethod string
	authUser   string
	authSecret string
}

// NewVaultLogicalBackend creates a new Vault logical backend that manages ensuring that
// the vault connection is up to date and authenticated.
func NewVaultLogicalBackend(client *api.Client, token string, authMethod string, authUser string, authSecret string) AuthableLogical {
	return &vaultBackend{
		client:     client,
		logical:    client.Logical(),
		token:      token,
		authMethod: authMethod,
		authUser: authUser,
		authSecret: authSecret,
	}
}

// Auth attempts to re-authenticate the backend and get a new token. It fails silently since we
// always want to retry (i.e. backend down, policies changing out from under us) when we can't.
func (b *vaultBackend) Auth() error {
	// If no token try and get one with authMethod
	if b.token == "" {
		var secret *api.Secret
		var err error

		switch b.authMethod {
		case "cert":
			path := fmt.Sprintf("auth/cert/login")
			secret, err = b.logical.Write(path, nil)
		case "ldap":
			path := fmt.Sprintf("auth/ldap/login/%s", b.authUser)

			ldapPassword := map[string]interface{}{
				"password": b.authSecret,
			}

			secret, err = b.logical.Write(path, ldapPassword)
		}

		if err != nil {
			return ErrAuthFailed{err}
		}

		if secret == nil {
			return ErrAuthFailed{nil}
		}

		b.token = secret.Auth.ClientToken
	}
	// Set the current token.
	b.client.SetToken(b.token)
	return nil
}

func (b *vaultBackend) Read(path string) (*api.Secret, error) {
	if b.token == "" {
		if err := b.Auth(); err != nil {
			return nil, err
		}
	}

	secret, err := b.logical.Read(path)
	if err != nil {
		err = narrowVaultError(err)
	}
	return secret, err
}

func (b *vaultBackend) List(path string) (*api.Secret, error) {
	if b.token == "" {
		if err := b.Auth(); err != nil {
			return nil, err
		}
	}

	secret, err := b.logical.List(path)
	if err != nil {
		err = narrowVaultError(err)
	}
	return secret, err
}

func (b *vaultBackend) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	if b.token == "" {
		if err := b.Auth(); err != nil {
			return nil, err
		}
	}

	secret, err := b.logical.Write(path, data)
	if err != nil {
		err = narrowVaultError(err)
	}
	return secret, err
}

func (b *vaultBackend) Delete(path string) (*api.Secret, error) {
	if b.token == "" {
		if err := b.Auth(); err != nil {
			return nil, err
		}
	}

	secret, err := b.logical.Delete(path)
	if err != nil {
		err = narrowVaultError(err)
	}
	return secret, err
}

func (b *vaultBackend) Unwrap(wrappingToken string) (*api.Secret, error) {
	if b.token == "" {
		if err := b.Auth(); err != nil {
			return nil, err
		}
	}

	secret, err := b.logical.Unwrap(wrappingToken)
	if err != nil {
		err = narrowVaultError(err)
	}
	return secret, err
}

// narrowVaultError wraps a returned error with a specific error type based on its content
func narrowVaultError(err error) error {
	if strings.Contains(err.Error(), "* permission denied") {
		return ErrAuth{ErrPermissionDenied{err}}
	}

	if !strings.Contains(err.Error(), "* missing client token") {
		return ErrAuth{ErrMissingClientToken{err}}
	}

	return ErrVaultInaccessible{err}
}

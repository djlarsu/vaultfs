# VaultFS

This is a fork of the original VaultFS project.

[![Build Status](https://travis-ci.org/wrouesnel/vaultfs.svg?branch=master)](https://travis-ci.org/wrouesnel/vaultfs)

VaultFS mounts arbitrary [Vault](https://vaultproject.io/) prefixes in a FUSE
filesystem. It also provides a Docker volume plugin to the do the same for your
containers.

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-generate-toc again -->
**Table of Contents**

- [VaultFS](#vaultfs)
- [Mounting](#mounting)
- [Docker](#docker)
- [License](#license)

<!-- markdown-toc end -->

# Installation

```shell
go get github.com/wrouesnel/vaultfs
env GOOS=linux go build github.com/wrouesnel/vaultfs
```

# Usage

VaultFS is one binary that can mount keys or run a Docker volume plugin to do so
for containers. Run `vaultfs --help` to see options not documented here.

## Mounting

```
Usage:
  vaultfs mount {mountpoint} [flags]

Flags:
  -r, --root string   root path for mountpoint (default "secret")

Global Flags:
      --config string            config file (default /etc/vaultfs)
      --log-destination string   log destination (file:/your/output, stdout:, journald:, or syslog://tag@host:port#protocol) (default "stdout:")
      --log-format string        log level (one of text or json) (default "text")
      --log-level string         log level (one of fatal, error, warn, info, or debug) (default "info")
  -t, --token string             The Vault Server token

```

To mount secrets, first create a mountpoint (`mkdir test`), then use `vaultfs`
to mount:

```shell
vaultfs mount --address=http://localhost:8200 -t 3a749a17-528e-e4b1-c28a-62e54f0098ae test
```

## Docker

```
Usage:
  vaultfs docker {mountpoint} [flags]

Flags:
  -a, --address string   vault address (default "https://localhost:8200")
  -i, --insecure         skip SSL certificate verification
  -s, --socket string    socket address to communicate with docker (default "/run/docker/plugins/vault.sock")
  -t, --token string     vault token

Global Flags:
      --config string            config file (default /etc/vaultfs)
      --log-destination string   log destination (file:/your/output, stdout:, journald:, or syslog://tag@host:port#protocol) (default "stdout:")
      --log-format string        log level (one of text or json) (default "text")
      --log-level string         log level (one of fatal, error, warn, info, or debug) (default "info")
```

To start the Docker plugin, create a directory to hold mountpoints (`mkdir
test`), then use `vaultfs` to start the server. When Docker volumes request a
volume (`docker run --volume-driver vault --volume
{prefix}:/container/secret/path`), the plugin will create mountpoints and manage
FUSE servers automatically.

```shell
vaultfs docker --address=http://localhost:8200 -t 3a749a17-528e-e4b1-c28a-62e54f0098ae test
```

# License

VaultFS is licensed under an
[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html) (see also:
[LICENSE](LICENSE))

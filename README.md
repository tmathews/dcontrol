# Deployment Controller

Deployment Controller is a small and simple utility that transfers data from one computer to another. It was 
created to make it easier for my teammates to update and restart processes on our servers.

You can use Before/After commands to run custom scripts to stop/start processes for targets.

## Goals

 * Be fast, easy, and most of all secure
 * Forget about passwords, use keys!
 * Avoid complexities of the cloud
 * Be flexible & cross platform

## Configuration

A TOML file is used for configuration. Place it somewhere such as `/etc/deployctl/conf.toml`

```
AuthorizedKeys = "authorized_keys" # See example below
BackupDirectory = "tmp/backups"

[[Targets]]
Name = "test"
Authorized = ["*"]
Filename = "bin/thing"
Before = "dobefore.sh"
After = "doafter.sh"
```

The authorized keys is a file of base64 encoded public keys, via the `generate` command, and their names. Use one line
per key & user.

```
MIICCgKCAgEAo+GmAsm41j0ZN14HLiNdS6DBlJY...kOs+UILwFJ0ggDSafG3i/6cCAwEAAQ== user
```
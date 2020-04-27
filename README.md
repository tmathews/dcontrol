# Deployment Controller

Deployment Controller (dcontrol) is a small and simple utility that transfers data from one computer to another. It was created to make it 
easier for my teammates to update and restart processes on our servers. 

The key feature is that it restarts the systemd targets you specify when the payload is successfully delivered. Originally I wanted to use 
DBUS to talk to systemd to get proper error information if it fails - this was never done as it was a quick project I did in my free time.

I'd advise you use the command before/after feature to control service restarts instead - we check the exit code of the program for success.

## Notices

 * As said above it is recommend to use the Before/After feature instead of systemd targets.
 * We'll probably remove the `BackupDirectory` option in the future and just use a temporary directory which can be overrided.

## Deployment String

We use a simple URL to specify credentials, see the example below.

`dcontrol deploy username:password@domain/unit filepath`

## Configuration

A TOML file is used for configuration. I'd advise you set it up in `/etc/dcontrol/conf.toml`. See an example of this file below:

```
BackupDirectory="/root/bak"

[[Actors]]
Name = "tom"
Password = "notaninsecurepassword"

[[Units]]
Name = "http-server"
SystemTargets = ["http"]
Filepath = "/etc/http-server/bin/http"
AllowedActors = ["tom"]
```

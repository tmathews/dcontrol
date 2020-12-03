package main

import (
	"archive/tar"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/tmathews/goio"
)

var ErrInvalidPayload = errors.New("invalid payload")

type ServerContext struct {
	C      *tls.Conn
	Config *Config
	Log    *log.Logger
}

func HandleServerConn(ctx ServerContext) error {
	if err := ctx.C.Handshake(); err != nil {
		return err
	}

	signature := GetSignature(ctx.C.ConnectionState().PeerCertificates[0])
	ctx.Log.Printf("Got connection! %s", signature)

	cmd, input, err := goio.ReadCommand(ctx.C)
	if err != nil {
		return err
	}
	ctx.Log.Printf("Got command '%s' input len(%d)", cmd, len(input))

	switch cmd {
	case CommandDEPLOY:
		// Just continue onto the next code.
		break
	case CommandPING:
		// Write the PONG by saying OK status. No need to write pong IMO...
		return goio.Ok(ctx.C)
	default:
		return goio.NotOk(ctx.C, StatusUnsupported, fmt.Sprintf("The command %s is unsupported.", cmd))
	}

	name, err := ctx.Config.GetSignatureName(signature)
	if err != nil {
		ctx.Log.Printf("GetSignatureName error: %s", err.Error())
		return goio.NotOk(ctx.C, StatusNotOK, "Failed to look up signature.")
	} else if len(name) == 0 {
		return goio.NotOk(ctx.C, StatusBlocked, fmt.Sprintf("You signature was not accepted."))
	}
	target := ctx.Config.GetTargetByName(string(input))
	if target == nil {
		return goio.NotOk(ctx.C, StatusNotExist, fmt.Sprintf("The target %s does not exist.", input))
	}
	if !target.Allows(name) {
		return goio.NotOk(ctx.C, StatusBlocked, fmt.Sprintf("You do not have permission to deploy this target."))
	}

	f, err := ioutil.TempFile(os.TempDir(), "deployctl-")
	if err != nil {
		ctx.Log.Println(err.Error())
		return goio.NotOk(ctx.C, StatusNotOK, fmt.Sprintf("There was an error creating a temporary file."))
	}
	defer f.Close()

	if err := goio.Ok(ctx.C); err != nil {
		return err
	}

	// Stream the data to our temporary file
	if err := goio.ReadStream(ctx.C, f); goio.IsClosed(err) {
		return err
	} else if err != nil {
		ctx.Log.Println(err.Error())
		return goio.NotOk(ctx.C, StatusNotOK, "The transmission was broken.")
	}

	tmpdir, err := PrepareTarget(f)
	if err != nil {
		return goio.NotOk(ctx.C, StatusNotOK, "Issue with relocating files.")
	} else if tmpdir != "" {
		defer os.RemoveAll(tmpdir)
	}
	f.Close()

	// Run our Before commands. Should be things like killing processes, etc.
	if err := RunScript(target.Before, ctx.Log); err != nil {
		ctx.Log.Println(err.Error())
		return goio.NotOk(ctx.C, StatusNotOK, "Issue running Before script.")
	}

	backup, err := BackupTarget(*target, ctx.Config.BackupDirectory)
	if err != nil {
		ctx.Log.Printf("BackupTarget error: %s", err.Error())
		return goio.NotOk(ctx.C, StatusNotOK, "Failed to backup the target. Please attend.")
	}

	restore := func() (err error) {
		err = os.RemoveAll(target.Filename)
		if err != nil {
			return
		}
		err = os.Rename(backup, target.Filename)
		if err != nil {
			return
		}
		return RunScript(target.After, ctx.Log)
	}

	if err := MoveTarget(tmpdir, target.Filename); err != nil {
		ctx.Log.Printf("MoveTarget error: %s", err.Error())
		msg := "Failed to move target files."
		if err == ErrInvalidPayload {
			msg = "Expected only one directory or file in the TAR payload."
		}
		if err := restore(); err != nil {
			ctx.Log.Printf("Restore error: %s", err.Error())
			msg += " Restoring from backup failed. Please attend."
		} else {
			msg += " Restore executed successfully."
		}
		return goio.NotOk(ctx.C, StatusNotOK, msg)
	}

	// Run our After command. i.e. Start the process up.
	if err := RunScript(target.After, ctx.Log); err != nil {
		ctx.Log.Printf("After error: %s", err.Error())
		msg := "Issue running After script."
		if err := restore(); err != nil {
			ctx.Log.Printf("Restore error: %s", err.Error())
			msg += " Restoring from backup failed. Please attend."
		} else {
			msg += " Restore executed successfully."
		}
		return goio.NotOk(ctx.C, StatusNotOK, msg)
	}

	// Delete the backup we created so we save disk space.
	if backup != "" {
		if err := os.RemoveAll(backup); err != nil {
			ctx.Log.Printf("Failed to delete backup: %v", err)
		}
	}

	return goio.Ok(ctx.C)
}

func MoveTarget(tmpdir, filename string) error {
	// Ensure that the parent directory for our target exists
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}

	// Ensure the payload has only 1 item
	xs, err := ioutil.ReadDir(tmpdir)
	if err != nil {
		return err
	} else if len(xs) != 1 {
		return ErrInvalidPayload
	}

	// Move it
	old := filepath.Join(tmpdir, xs[0].Name())
	return os.Rename(old, filename)
}

func BackupTarget(target Target, dir string) (string, error) {
	// Ensure the backup destination exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	// Ensure there is something to backup
	_, err := os.Stat(target.Filename)
	if os.IsNotExist(err) {
		// This handles the case where the binary never existed before.
		return "", nil
	} else if err != nil {
		return "", err
	}

	// Move it
	str := path.Join(dir, target.Name+time.Now().Format(".20060102150405.bak"))
	return str, os.Rename(target.Filename, str)
}

func PrepareTarget(rs io.ReadSeeker) (string, error) {
	if _, err := rs.Seek(0, 0); err != nil {
		return "", err
	}
	return UnpackTar(tar.NewReader(rs))
}

func RunScript(command string, log *log.Logger) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	xs := strings.Split(command, " ")
	if len(xs) == 0 {
		return nil
	}
	var arguments []string
	if len(xs) >= 2 {
		arguments = xs[1:]
	}
	cmd := exec.Command(xs[0], arguments...)
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

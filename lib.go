package main

import (
	"archive/tar"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	DefaultAddress = "0.0.0.0:20384"
)

type Config struct {
	// A list of hex signatures that is accepted. Each signature should possess a name at the end separated by a space.
	// Signatures without names are ignored.
	Signatures []string

	// All the targets configured for deployment.
	Targets []Target

	// Previous versions of targets that are deployed will be placed here.
	BackupDirectory string
}

func (c *Config) GetSignatures() map[string]string {
	m := make(map[string]string, len(c.Signatures))
	for _, v := range c.Signatures {
		xs := strings.SplitN(v, " ", 2)
		if len(xs) != 2 {
			continue
		}
		m[xs[1]] = xs[0]
	}
	return m
}

func (c *Config) IsValidSignature(signature string) bool {
	return c.GetSignatureName(signature) != ""
}

func (c *Config) GetSignatureName(signature string) string {
	for _, v := range c.Signatures {
		xs := strings.SplitN(v, " ", 2)
		if len(xs) != 2 {
			continue
		}
		if v == signature {
			return strings.TrimSpace(xs[1])
		}
	}
	return ""
}

func (c *Config) GetTargetByName(name string) *Target {
	for _, v := range c.Targets {
		if v.Name == name {
			return &v
		}
	}
	return nil
}

type Target struct {
	Name string

	// This field determines which signatures, by name, can deploy this unit. Putting a * enables all actors.
	Authorized []string

	// The absolute path which to replace when uploading a unit's new files.
	Filename string

	// Before & After are shell commands to run during the process replacing the units files. If any shell commands
	// results in a status of non-0 a rollback will occur. If you need more than one command, perhaps you should write
	// a script that runs them all instead.
	Before string
	After  string
}

func (t *Target) Allows(name string) bool {
	for _, v := range t.Authorized {
		if v == "*" || v == name {
			return true
		}
	}
	return false
}


func IsProjectPath(p string, ignore []string) bool {
	for _, v := range ignore {
		if strings.Contains(p, v) {
			return true
		}
	}
	return false
}

// Should pack a single item, dir or file, into a tar. This is so that we can
// assume that the 1 item inside will replace what's on the server.
func PackTar(filename string, w io.Writer, ignore []string) error {
	fp, err := filepath.Abs(filename)
	if err != nil {
		return err
	}

	writer := tar.NewWriter(w)
	defer writer.Close()

	return filepath.Walk(fp, func(p string, info os.FileInfo, err error) error {
		if IsProjectPath(p, ignore) {
			return nil
		}

		if err != nil {
			return err
		}

		h, err := tar.FileInfoHeader(info, info.Name())
		if v, err := filepath.Rel(filepath.Dir(fp), p); err != nil {
			return err
		} else {
			h.Name = filepath.ToSlash(v)
		}
		if err != nil {
			return err
		}
		if err := writer.WriteHeader(h); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(writer, f); err != nil {
			return err
		}
		return nil
	})
}

// Creates a temporary directory to dump the contents of the tar to and returns
// the file path
func UnpackTar(reader *tar.Reader) (dir string, err error) {
	dir, err = ioutil.TempDir(os.TempDir(), "deployctl-")
	if err != nil {
		return
	}

	for {
		var h *tar.Header
		h, err = reader.Next()
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}
		if h == nil {
			continue
		}

		mode := os.FileMode(h.Mode & 0x0fff)
		fp := path.Join(dir, h.Name)
		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(fp, mode)
			if err != nil {
				return
			}
		case tar.TypeReg:
			var f *os.File
			f, err = os.OpenFile(fp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return
			}
			_, err = io.Copy(f, reader)
			if err != nil {
				f.Close()
				return
			}
			f.Close()
		}
	}
	return
}

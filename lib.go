package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort       = 20384
	bufferSize  int64 = 1024
)

// Systemd CLI actions
const (
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"
)

type Conf struct {
	Actors          []Actor
	Units           []Unit
	BackupDirectory string
}

type Actor struct {
	Name     string
	Password string
}

type Unit struct {
	AllowedActors []string
	Filepath      string // The payload which will be replaced. May be file or entire directory
	Name          string
	SystemTargets []string // Names of all systemd processes to restart.
}

// Loops through the connection to copy the appropriate bytes into memory
func ReadConnSec(conn net.Conn, length int64) ([]byte, error) {
	var buf []byte
	var receivedBytes int64
	writer := bytes.NewBuffer(buf)
	for {
		if receivedBytes >= length {
			break
		}
		size := bufferSize
		remaining := length - receivedBytes
		if remaining < size {
			size = remaining
		}
		if _, err := io.CopyN(writer, conn, size); err != nil {
			return nil, err
		}
		receivedBytes += size
	}
	return writer.Bytes(), nil
}

// Reads next portion of connection to a fixed length of 10 to parse an int
// TODO in future instead of passing size as a string just pass it as byte data
func ReadConnFileSize(conn net.Conn) (int64, error) {
	bufFileSize := make([]byte, 10)
	if _, err := conn.Read(bufFileSize); err != nil {
		return 0, err
	}
	return strconv.ParseInt(TrimZeroStr(string(bufFileSize)), 10, 64)
}

func ReadConnInt64(conn net.Conn) (int64, error) {
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err != nil {
		return 0, err
	}
	i, n := binary.Varint(buf)
	if n <= 0 {
		return 0, errors.New("int64 read issue")
	}
	return i, nil
}

// Reads section of connection to parse a string, 0 byte characters are trimmed
func ReadConnStr(conn net.Conn, length int64) (string, error) {
	buf := make([]byte, length)
	if _, err := conn.Read(buf); err != nil {
		return "", err
	}
	return TrimZeroStr(string(buf[:])), nil
}

func WriteConnFileSize(conn net.Conn, size int) error {
	return WriteConnStr(conn, strconv.Itoa(size), 10)
}

// This will pad the string with 0 if the string is too short, otherwise it will
// truncate the string to fit the length
func WriteConnStr(conn net.Conn, str string, length int64) error {
	buf := make([]byte, length)
	copy(buf[:], str)
	_, err := conn.Write(buf[:])
	return err
}

func WriteConnInt64(conn net.Conn, i int64) error {
	buf := make([]byte, 8)
	binary.PutVarint(buf, i)
	_, err := conn.Write(buf)
	return err
}

func Pack(filename string, pass string) ([]byte, error) {
	data, err := PackTar(filename)
	if err != nil {
		return nil, err
	}
	// Encrypt data using password
	return Encrypt(data, pass)
}

// This is the main function used by the daemon to accept a payload, it does too
// much work atm. I'll clean up if I ever feel like it, but for now it works well.
func AcceptPayload(c Conf, conn net.Conn) error {
	// First 64 bytes must be unit's name
	unitName, err := ReadConnStr(conn, 64)
	if err != nil {
		return err
	}
	// Second 64 bytes must be actor's name
	actor, err := ReadConnStr(conn, 64)
	if err != nil {
		return err
	}
	// Next 8 bytes must be the tar file's size, we'll read the tar in a second!
	fileSize, err := ReadConnInt64(conn)
	if err != nil {
		return err
	}

	// Make sure user exists before continuing
	if !CheckAuth(c, unitName, actor) {
		return errors.New(fmt.Sprintf("invalid authorization, actor name '%s', unit name '%s'", actor, unitName))
	}

	// Read the tar into memory
	tarBuf, err := ReadConnSec(conn, fileSize)
	if err != nil {
		return err
	}

	// Decrypt tar file with actor's password
	data, err := Decrypt(tarBuf, GetPass(c, actor))
	if err != nil {
		return err
	}
	dir, err := UnpackTar(tar.NewReader(bytes.NewReader(data)))
	if dir != "" {
		defer os.RemoveAll(dir)
	}
	if err != nil {
		return err
	}

	unit := GetUnit(c, unitName)

	// Halt unit to commence deployment
	if err := TriggerUnit(unit, ActionStop); err != nil {
		return err
	}

	// Ensure parent dir of unit exists
	err = os.MkdirAll(path.Dir(unit.Filepath), os.FileMode(0755))
	if err != nil {
		return err
	}

	// Move existing unitName path to safe place
	var backupExists bool
	var backupPath string
	_, err = os.Stat(unit.Filepath)
	if err == nil {
		backupExists = true
		backupPath := path.Join(c.BackupDirectory, unit.Name+time.Now().Format(".20060102150405.bak"))
		err := os.Rename(unit.Filepath, backupPath)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	// Find the single item in the tmp dir to use
	xs, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(xs) != 1 {
		return errors.New(fmt.Sprintf("expected a single item in tar, got %s", len(xs)))
	}

	// Move temp dir to path
	if err := os.Rename(filepath.Join(dir, xs[0].Name()), unit.Filepath); err != nil {
		return err
	}

	// Start unit back up and check for smooth sailings, if not rollback the deployment
	if err := TriggerUnit(unit, ActionStart); err != nil {
		if backupExists {
			if err := os.Rename(backupPath, unit.Filepath); err != nil {
				return err
			}
			return TriggerUnit(unit, ActionRestart)
		}
		return err
	}

	return nil
}

func TriggerUnit(unit Unit, action string) error {
	// TODO in future we need to do a dbus call & check errors!
	for _, target := range unit.SystemTargets {
		fmt.Printf("exec: systemctl %s %s\n", action, target)
		cmd := exec.Command("systemctl", action, target)

		if r, err := cmd.StdoutPipe(); err != nil {
			io.Copy(os.Stdout, r)
		}
		if r, err := cmd.StderrPipe(); err != nil {
			io.Copy(os.Stderr, r)
		}

		err := cmd.Start()
		if err != nil {
			fmt.Println(err)
		}
	}
	time.Sleep(time.Millisecond * 500)
	return nil
}

// Should pack a single item, dir or file, into a tar. This is so that we can
// assume that the 1 item inside will replace what's on the server.
func PackTar(filename string) ([]byte, error) {
	fp, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer([]byte{})
	writer := tar.NewWriter(buf)
	defer writer.Close()

	err = filepath.Walk(fp, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		h, err := tar.FileInfoHeader(info, info.Name())
		h.Name, _ = filepath.Rel(filepath.Dir(fp), path)
		if err != nil {
			return err
		}
		if err := writer.WriteHeader(h); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(writer, f); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Creates a temporary directory to dump the contents of the tar to and returns
// the file path
func UnpackTar(reader *tar.Reader) (dir string, err error) {
	dir, err = ioutil.TempDir(os.TempDir(), "dcontrol-")
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

		mode := os.FileMode(h.Mode&0x0fff)
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

func GetUnit(c Conf, name string) Unit {
	for _, x := range c.Units {
		if x.Name == name {
			return x
		}
	}
	return Unit{}
}

func GetPass(c Conf, name string) string {
	for _, x := range c.Actors {
		if x.Name == name {
			return x.Password
		}
	}
	return ""
}

func CheckAuth(c Conf, unit, name string) bool {
	// Check actor exists
	var xs []string
	for _, x := range c.Actors {
		xs = append(xs, x.Name)
	}
	if !StrInList(xs, name) {
		return false
	}

	// Check unit exists && check actor allowed for unit
	xs = []string{}
	for _, x := range c.Units {
		if x.Name == unit && !StrInList(x.AllowedActors, name) {
			return false
		}
		xs = append(xs, x.Name)
	}
	if !StrInList(xs, unit) {
		return false
	}

	return true
}

func TrimZeroStr(str string) string {
	return strings.Trim(str, string([]byte{0}))
}

func StrInList(xs []string, x string) bool {
	for _, y := range xs {
		if x == y {
			return true
		}
	}
	return false
}

func CreateHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(CreateHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	zipher := gcm.Seal(nonce, nonce, data, nil)
	return zipher, nil
}

func Decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(CreateHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, zipher := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, zipher, nil)
}

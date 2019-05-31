package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
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

	"github.com/BurntSushi/toml"
	cmd "github.com/tmathews/commander"
)

const defaultPort = 20384
const bufferSize int64 = 1024

func main() {
	var args []string
	if len(os.Args) >= 2 {
		args = os.Args[1:]
	}
	err := cmd.Exec(args, cmd.Manual("Welcome to dcontrol", "JUST DO IT!\n"), cmd.M{
		"daemon": cmdDaemon,
		"deploy": cmdDeploy,
	})
	if err != nil {
		switch v := err.(type) {
		case cmd.Error:
			fmt.Print(v.Help())
			os.Exit(2)
		default:
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}
}

type Conf struct {
	Actors []Actor
	Units  []Unit
	BackupDirectory string
}

type Actor struct {
	Name     string
	Password string
}

type Unit struct {
	AllowedActors  []string
	Filepath       string   // The payload which will be replaced. May be file or entire directory
	Name           string
	SystemTargets []string // Names of all systemd processes to restart.
}

func cmdDaemon(name string, args []string) error {
	var port int
	var confFilename string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.IntVar(&port, "port", defaultPort, "Port to run on.")
	set.StringVar(&confFilename, "c", "./dcontrol.toml", "Location of config file.")
	if err := set.Parse(args); err != nil {
		return err
	}

	conf, err := loadConf(confFilename)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(conf.BackupDirectory, 0755); err != nil {
		return err
	}

	// Open server and listen for payloads
	server, err := net.Listen("tcp", "localhost:"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Println("Listening")
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}
		go func() {
			defer connection.Close()
			err := acceptPayload(conf, connection)
			if err != nil {
				fmt.Print(err)
				// TODO send error back to client
			}
		}()
	}
}

func cmdDeploy(name string, args []string) error {
	var port int
	var actorName string
	var pass string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.IntVar(&port, "port", defaultPort, "Port to run on.")
	set.StringVar(&actorName, "name", "", "Actor name")
	set.StringVar(&pass, "pass", "", "Actor password")
	if err := set.Parse(args); err != nil {
		return err
	}
	unitName := set.Arg(0)
	filename := set.Arg(1)

	if unitName == "" {
		return errors.New("empty unit name")
	}
	if filename == "" {
		return errors.New("empty filename provided")
	}

	data, err := pack(filename, pass)
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", "localhost:"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	var unitNameBuf [64]byte
	var actorNameBuf [64]byte
	var fileSizeBuf [10]byte

	fmt.Println(len(data))

	copy(unitNameBuf[:], unitName)
	copy(actorNameBuf[:], actorName)
	copy(fileSizeBuf[:], strconv.Itoa(len(data)))

	if _, err := conn.Write(unitNameBuf[:]); err != nil {
		return err
	}
	if _, err := conn.Write(actorNameBuf[:]); err != nil {
		return err
	}
	if _, err := conn.Write(fileSizeBuf[:]); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}

	// Read results from connection!

	return conn.Close()
}

func pack(filename string, pass string) ([]byte, error) {
	data, err := PackTar(filename)
	if err != nil {
		return nil, err
	}
	// Encrypt data using password
	return encrypt(data, pass)
}

func PackTar(filename string) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	writer := tar.NewWriter(buf)
	defer writer.Close()

	_ = filepath.Walk(filename, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(info, info.Name())
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
	return buf.Bytes(), nil
}

func loadConf(filename string) (Conf, error) {
	var c Conf
	_, err := toml.DecodeFile(filename, &c)
	return c, err
}

func acceptPayload(c Conf, conn net.Conn) error {
	bufUnit := make([]byte, 64)     // First 64 bytes must be unitName name
	bufActor := make([]byte, 64)    // Second 64 bytes must be credentials
	bufFileSize := make([]byte, 10) // Next 10 bytes must be files size

	if _, err := conn.Read(bufUnit); err != nil {
		return err
	}
	if _, err := conn.Read(bufActor); err != nil {
		return err
	}
	if _, err := conn.Read(bufFileSize); err != nil {
		return err
	}

	unitName := TrimZeroStr(string(bufUnit[:]))
	actor := TrimZeroStr(string(bufActor[:]))

	// Make sure user exists before continuing
	if !CheckAuth(c, unitName, actor) {
		return errors.New(fmt.Sprintf("invalid authorization, actor name '%s', unit name '%s'", actor, unitName))
	}

	unit := GetUnit(c, unitName)

	// Read the file into a temporary location using recieved file size
	fileSize, err := strconv.ParseInt(TrimZeroStr(string(bufFileSize)), 10, 64)
	if err != nil {
		return err
	}
	fmt.Println(fileSize)

	var tarBuf []byte
	var receivedBytes int64
	writer := bytes.NewBuffer(tarBuf)
	for {
		if receivedBytes >= fileSize {
			break
		}
		size := bufferSize
		remaining := fileSize - receivedBytes
		if remaining < size {
			size = remaining
		}
		if _, err := io.CopyN(writer, conn, size); err != nil{
			return err
		}
		receivedBytes += size
	}

	// Decrypt zip file with actor's password
	data, err := decrypt(writer.Bytes(), GetPass(c, actor))
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

	// Ensure parent dir of unit exists
	err = os.MkdirAll(path.Dir(unit.Filepath), os.FileMode(0755))
	if err != nil {
		return err
	}

	// Move existing unitName path to safe place
	_, err = os.Stat(unit.Filepath)
	if err == nil {
		newPath := path.Join(c.BackupDirectory, unit.Name + time.Now().Format(".20060102150405.bak"))
		err := os.Rename(unit.Filepath, newPath)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	// Move temp dir to path
	if err := os.Rename(dir, unit.Filepath); err != nil {
		return err
	}

	if err := RestartUnit(unit); err != nil {
		// TODO move backup back and try restarting again, if fail say so
		return err
	}

	return nil
}

func RestartUnit(unit Unit) error {
	// TODO in future we need to do a dbus call & check errors!
	for _, target := range unit.SystemTargets {
		exec.Command("systemd", "restart", target)
	}
	return nil
}

func UnpackTar(reader *tar.Reader) (dir string, err error) {
	dir, err = ioutil.TempDir(os.TempDir(), "dcontrol-")
	if err != nil {
		return
	}

	for {
		var h *tar.Header
		h, err = reader.Next()
		fmt.Println(err)
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}
		if h == nil {
			continue
		}

		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(path.Join(dir, h.Name), os.FileMode(0755))
			if err != nil {
				return
			}
		case tar.TypeReg:
			var f *os.File
			f, err = os.Create(path.Join(dir, h.Name))
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

func StrInList(xs []string, x string) bool {
	for _, y := range xs {
		if x == y {
			return true
		}
	}
	return false
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	zipher := gcm.Seal(nonce, nonce, data, nil)
	return zipher , nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
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

func TrimZeroStr(str string) string {
	return strings.Trim(str, string([]byte{0}))
}
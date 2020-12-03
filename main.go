package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	arc "github.com/tmathews/arcnet"
	cmd "github.com/tmathews/commander"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	var args []string
	if len(os.Args) >= 2 {
		args = os.Args[1:]
	}
	err := cmd.Exec(args, cmd.Manual("Welcome to deployctl.", "Send it!\n"), cmd.M{
		"daemon": cmdDaemon,
		"send":   cmdSend,
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

func AppDir() string {
	switch runtime.GOOS {
	case "linux":
		return "/etc/deployctl"
	}
	return ""
}

func AppFilename(str string) string {
	return filepath.Join(AppDir(), str)
}

func cmdDaemon(name string, args []string) error {
	var address, confFilename, certFilename, keyFilename string
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.StringVar(&address, "address", DefaultAddress, "Address to bind to.")
	set.StringVar(&confFilename, "config", AppFilename("conf.toml"), "Location of config file.")
	set.StringVar(&certFilename, "cert", AppFilename("cert"), "")
	set.StringVar(&keyFilename, "key", AppFilename("key"), "")
	if err := set.Parse(args); err != nil {
		return err
	}

	var conf Config
	if _, err := toml.DecodeFile(confFilename, &conf); err != nil {
		return err
	}
	if err := os.MkdirAll(conf.BackupDirectory, 0755); err != nil {
		return err
	}

	server := &arc.Server{}
	listener, err := server.Listen(address, true)
	if err != nil {
		return err
	}

	log.Printf("Server opened on %s.\n", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go func() {
			ctx := ServerContext{
				C:      tls.Server(conn, server.Conf),
				Config: &conf,
				Log:    log.New(os.Stdout, "", log.LstdFlags),
			}
			err := HandleServerConn(ctx)
			if arc.IsClosed(err) {
				log.Println("Client got disconnected.")
			} else if err != nil {
				conn.Close()
			}
		}()
	}
}

// TODO improve ignore functionality to be glob based.
func cmdSend(name string, args []string) error {
	var ignoreStr, certFilename, keyFilename string
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.StringVar(&ignoreStr, "i", fmt.Sprintf("%[1]c.git,%[1]c.idea", filepath.Separator), "Ignore project files")
	set.StringVar(&certFilename, "cert", AppFilename("cert"), "")
	set.StringVar(&keyFilename, "key", AppFilename("key"), "")
	if err := set.Parse(args); err != nil {
		return err
	}
	address := set.Arg(0)
	target  := set.Arg(1)
	filename := set.Arg(2)

	// TODO have more verbose details on each argument error
	if len(address) == 0 || len(target) == 0 || len(filename) == 0 {
		return errors.New("Arguments missing; please check your input.")
	}

	var ignore []string
	if xs := strings.Split(ignoreStr, ","); len(xs) > 0 {
		for _, v := range xs {
			v = strings.TrimSpace(v)
			if len(v) > 0 {
				ignore = append(ignore, v)
			}
		}
	}

	cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
	if err != nil {
		return err
	}
	conf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	fmt.Println("Dialing...")
	c, err := tls.Dial("tcp", address, conf)
	if err != nil {
		return err
	}
	defer c.Close()

	return HandleClientConn(c, target, filename, ignore)
}

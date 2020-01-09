package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	cmd "github.com/tmathews/commander"
)

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

func cmdDaemon(name string, args []string) error {
	var port int
	var confFilename string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.IntVar(&port, "port", defaultPort, "Port to run on.")
	set.StringVar(&confFilename, "c", "./dcontrol.toml", "Location of config file.")
	if err := set.Parse(args); err != nil {
		return err
	}

	var conf Conf
	if _, err := toml.DecodeFile(confFilename, &conf); err != nil {
		return err
	}
	if err := os.MkdirAll(conf.BackupDirectory, 0755); err != nil {
		return err
	}

	// Open server and listen for payloads
	server, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Println("Listening")
	for {
		conn, err := server.Accept()
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}
		go func() {
			defer conn.Close()
			var response string
			err := AcceptPayload(conf, conn)
			if err != nil {
				fmt.Print(err)
				response = err.Error()
			} else {
				response = "OK!"
			}
			if err := WriteConnInt64(conn, int64(len(response))); err != nil {
				fmt.Println(err)
			}
			if _, err := conn.Write([]byte(response)); err != nil {
				fmt.Println(err)
			}
		}()
	}
}

func cmdDeploy(name string, args []string) error {
	var ignoreStr string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.StringVar(&ignoreStr, "i", fmt.Sprintf("%[1]c.git,%[1]c.idea", filepath.Separator), "Ignore project files")
	set.BoolVar(&Verbose, "v", false, "Be verbose")
	if err := set.Parse(args); err != nil {
		return err
	}

	if xs := strings.Split(ignoreStr, ","); len(xs) > 0 {
		for _, v := range xs {
			v = strings.TrimSpace(v)
			if len(v) > 0 {
				IgnoreFiles = append(IgnoreFiles, v)
			}
		}
	}

	connStr := set.Arg(0)
	filename := set.Arg(1)

	if connStr == "" {
		return errors.New("empty connection string")
	}
	connStr = "//" + connStr

	if filename == "" {
		return errors.New("empty filename provided")
	}

	u, err := url.Parse(connStr)
	if err != nil {
		return err
	}

	port := u.Port()
	unitName := path.Base(u.Path)
	actorName := u.User.Username()
	password, _ := u.User.Password()

	if actorName == "" {
		return errors.New("empty actor name provided")
	}
	if password == "" {
		return errors.New("empty password provided.")
	}
	if unitName == "" {
		return errors.New("empty unit name")
	}
	if port == "" {
		port = strconv.Itoa(defaultPort)
	}

	data, err := Pack(filename, password)
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", u.Hostname()+":"+port)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Write all the data in the correct order: unitName(64), actorName(64), size(8), data(N)
	if err := WriteConnStr(conn, unitName, 64); err != nil {
		return err
	}
	if err := WriteConnStr(conn, actorName, 64); err != nil {
		return err
	}
	if err := WriteConnInt64(conn, int64(len(data))); err != nil {
		return err
	}
	if n, err := conn.Write(data); err != nil {
		return err
	} else {
		fmt.Printf("Wrote %d bytes.\n", n)
	}
	fmt.Printf("Waiting...\n")

	// Read the response and print it!
	strLength, err := ReadConnInt64(conn)
	if err != nil {
		return err
	}
	response, err := ReadConnStr(conn, strLength)
	if err != nil {
		return err
	}
	fmt.Printf("Response: %s\n", response)

	return nil
}

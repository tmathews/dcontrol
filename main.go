package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	cmd "github.com/tmathews/commander"
	arc "github.com/tmathews/goio"
)

const appName = "deployctl"

func main() {
	var args []string
	if len(os.Args) >= 2 {
		args = os.Args[1:]
	}
	err := cmd.Exec(args, cmd.Manual(fmt.Sprintf("Welcome to %s.", appName), "Send it!\n"), cmd.M{
		"generate": cmdGenerate,
		"daemon":   cmdDaemon,
		"send":     cmdSend,
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

func cmdGenerate(name string, args []string) error {
	var org string
	var d time.Duration
	var pub bool
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.StringVar(&org, "organization", "", "Organization name to use for certificate.")
	set.DurationVar(&d, "duration", time.Hour*24*365*5, "How long should this certificate last?")
	set.BoolVar(&pub, "public-key", false, "Print the public key from the provided filepath instead.")
	set.Usage = func() {
		fmt.Printf("\n%s %s <filename>\n\n<filename> should be the location where credentials are read/wrote.\n\n", appName, name)
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		return err
	}

	loc := set.Arg(0)
	if stat, err := os.Stat(filepath.Dir(loc)); os.IsNotExist(err) {
		return &FlagError{
			Flag:   "filepath",
			Reason: "The provided filepath does not exist, please check your input.",
		}
	} else if err != nil {
		return &FlagError{
			Flag:   "filepath",
			Reason: err.Error(),
		}
	} else if !stat.IsDir() {
		return &FlagError{
			Flag:   "filepath",
			Reason: "The filepath provided is not a valid directory placement.",
		}
	}

	var cert *x509.Certificate
	if !pub {
		var key *rsa.PrivateKey
		var err error
		cert, key, err = arc.GenerateCerts(org, d)
		if err != nil {
			return err
		}
		if err = arc.WriteCertificate(cert, loc+".cert"); err != nil {
			return err
		}
		if err = arc.WritePrivateKey(key, loc+".key"); err != nil {
			return err
		}
		fmt.Println("Certificate & key generated.")
	} else {
		if c, err := tls.LoadX509KeyPair(loc+".cert", loc+".key"); err != nil {
			return err
		} else {
			cert, err = x509.ParseCertificate(c.Certificate[0])
			if err != nil {
				return err
			}
		}
	}

	signature := GetSignature(cert)
	fmt.Printf("Public Key:\n%s", signature)

	return nil
}

func cmdDaemon(name string, args []string) error {
	var address, confFilename, certFilename, keyFilename string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.StringVar(&address, "address", DefaultAddress, "Address to bind to.")
	set.StringVar(&confFilename, "config", AppFilename("conf.toml"), "Location of config file.")
	set.StringVar(&certFilename, "cert", AppFilename("cert"), "")
	set.StringVar(&keyFilename, "key", AppFilename("key"), "")
	set.Usage = func() {
		fmt.Printf("\n%s %s\n\n", appName, name)
		set.PrintDefaults()
	}
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
	if err := server.LoadCert(certFilename, keyFilename); err != nil {
		return err
	}
	listener, err := server.Listen(address, true)
	if err != nil {
		return err
	}

	log.Printf("Server opened on %s.\n", address)
	var logId int

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go func() {
			logId++
			ctx := ServerContext{
				C:      tls.Server(conn, server.Conf),
				Config: &conf,
				Log:    log.New(os.Stdout, fmt.Sprintf("con[%d] ", logId), log.LstdFlags),
			}
			err := HandleServerConn(ctx)
			if arc.IsClosed(err) {
				ctx.Log.Println("Client got disconnected.")
			} else if err != nil {
				ctx.Log.Println(err)
				conn.Close()
			}
		}()
	}
}

func cmdSend(name string, args []string) error {
	var ignoreStr, certFilename, keyFilename string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.StringVar(&ignoreStr, "i", fmt.Sprintf("%[1]c.git,%[1]c.idea", filepath.Separator), "Ignore project files")
	set.StringVar(&certFilename, "cert", AppFilename("cert"), "")
	set.StringVar(&keyFilename, "key", AppFilename("key"), "")
	set.Usage = func() {
		fmt.Printf(`
%s %s <address> <target> <filename>

<address>  the server address and port to send to e.g. %s
<target>   the target name to deploy
<filename> the filepath to a directory or file which is to be sent as the target

`, appName, name, DefaultAddress)
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		return err
	}

	address := set.Arg(0)
	target := set.Arg(1)
	filename := set.Arg(2)
	if len(address) == 0 {
		return &ArgError{Argument: "address", Position: 1, Reason: "Missing"}
	}
	if len(target) == 0 {
		return &ArgError{Argument: "target", Position: 2, Reason: "Missing"}
	}
	if len(filename) == 0 {
		return &ArgError{Argument: "filename", Position: 3, Reason: "Missing"}
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

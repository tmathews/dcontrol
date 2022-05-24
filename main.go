package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	cmd "github.com/tmathews/commander"
	"github.com/tmathews/goio"
)

const appName = "dctl"

func main() {
	var args []string
	if len(os.Args) >= 2 {
		args = os.Args[1:]
	}
	err := cmd.Exec(args, cmd.Manual(fmt.Sprintf("Welcome to %s.", appName), "Send it!\n"), cmd.M{
		"generate":  cmdGenerate,
		"daemon":    cmdDaemon,
		"send":      cmdSend,
		"ping":      cmdPing,
		"test-keys": cmdTestKeys,
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
		fmt.Printf("\n%s %s [flags...] <filename>\n\n<filename> should be the location where credentials are read/wrote.\n\n", appName, name)
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
		cert, key, err = goio.GenerateCerts(org, d)
		if err != nil {
			return err
		}
		if err = goio.WriteCertificate(cert, loc+".cert"); err != nil {
			return err
		}
		if err = goio.WritePrivateKey(key, loc+".key"); err != nil {
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
		fmt.Printf("\n%s %s [flags...]\n\n", appName, name)
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

	server := &goio.Server{}
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
			if goio.IsClosed(err) {
				ctx.Log.Println("Client got disconnected.")
			} else if err != nil {
				ctx.Log.Println(err)
				conn.Close()
			}
		}()
	}
}

func cmdPing(name string, args []string) error {
	var certFilename, keyFilename string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.StringVar(&certFilename, "cert", UsrFilename("cert"), "")
	set.StringVar(&keyFilename, "key", UsrFilename("key"), "")
	set.Usage = func() {
		fmt.Printf(`
%s %s [flags...] <address>

<address>  the server address and port to send to e.g. %s

`, appName, name, DefaultAddress)
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		return err
	}

	address := set.Arg(0)
	if len(address) == 0 {
		return &ArgError{Argument: "address", Position: 1, Reason: "Missing"}
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

	err = HandleClientConnPing(tls.Client(c, conf))
	if err != nil {
		return err
	}
	fmt.Println("PING successful!")
	return nil
}

func cmdSend(name string, args []string) error {
	var ignoreStr, certFilename, keyFilename string
	set := flag.NewFlagSet(name, flag.ExitOnError)
	set.StringVar(&ignoreStr, "ignore", fmt.Sprintf("%[1]c.git,%[1]c.idea", filepath.Separator), "Ignore project files")
	set.StringVar(&certFilename, "cert", UsrFilename("cert"), "")
	set.StringVar(&keyFilename, "key", UsrFilename("key"), "")
	set.Usage = func() {
		fmt.Printf(`
%s %s [flags...] <address> <target> <filename>

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

	return HandleClientConn(tls.Client(c, conf), target, filename, ignore)
}

func cmdTestKeys(name string, args []string) error {
	root := "C:\\Go\\src\\github.com\\tmathews\\dcontrol\\.ssh\\"

	//cert := root + "id_rsa.pub"
	loadSSH(root + "id_rsa")

	return nil
	//certificate, err := tls.X509KeyPair()
	//fmt.Println(certificate)
	//return err
}

func loadSSH(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	buf, _ := ioutil.ReadAll(f)

	priv, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		panic(err)
	}

	parsedCryptoKey := priv.PublicKey().(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()
	pub := pubCrypto.(*rsa.PublicKey)

	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	})

	fmt.Printf("%s\n", encoded)

	/*
		// First, generate the test RSA keypair in SSH format
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		rsaPub := priv.PublicKey
		sshPub, err := ssh.NewPublicKey(&rsaPub)
		if err != nil {
			log.Fatal(err)
		}
		sshPubBytes := sshPub.Marshal()

		// Now we can convert it back to PEM format
		// Remember: if you're reading the public key from a file, you probably
		// want ssh.ParseAuthorizedKey.
		parsed, err := ssh.ParsePublicKey(sshPubBytes)
		if err != nil {
			log.Fatal(err)
		}
		// To get back to an *rsa.PublicKey, we need to first upgrade to the
		// ssh.CryptoPublicKey interface
		parsedCryptoKey := parsed.(ssh.CryptoPublicKey)

		// Then, we can call CryptoPublicKey() to get the actual crypto.PublicKey
		pubCrypto := parsedCryptoKey.CryptoPublicKey()

		// Finally, we can convert back to an *rsa.PublicKey
		pub := pubCrypto.(*rsa.PublicKey)

		// After this, it's encoding to PEM - same as always
		encoded := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub),
		})
		fmt.Printf("%s", encoded)
	*/
}

func loadBlock(filename string) []byte {
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf, _ := ioutil.ReadAll(f)
	fmt.Println(string(buf))
	fmt.Println("<<<-----")

	p, _ := pem.Decode(buf)
	fmt.Println(p.Type)
	fmt.Println("<<<-----")
	fmt.Println(p.Headers)
	fmt.Println("<<<-----")
	fmt.Println(len(p.Bytes))
	fmt.Println("<<<----- TRY PARSING IT")

	parsers := []func([]byte) (any, error){
		x509.ParsePKCS8PrivateKey,
		func(buf []byte) (any, error) { return x509.ParseECPrivateKey(buf) },
		func(buf []byte) (any, error) { return x509.ParsePKCS1PrivateKey(buf) },
	}
	var key any
	for _, parser := range parsers {
		key, err = parser(p.Bytes)
		if err == nil {
			break
		} else {
			fmt.Println(err)
		}
	}
	fmt.Println("KEY-->>>", key)

	return buf
}

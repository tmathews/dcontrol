package main

import (
	"crypto/tls"
	"fmt"

	"github.com/tmathews/goio"
)

func HandleClientConn(conn *tls.Conn, target, filename string, ignored []string) error {
	if err := conn.Handshake(); err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println("proceeding with command")
	err := goio.Command(conn, CommandDEPLOY, target)
	if err != nil {
		return err
	}

	sw := goio.NewStreamWriter(conn)
	err = PackTar(filename, sw, ignored)
	sw.Terminate()
	if err != nil {
		return err
	}
	return goio.ReadStatus(conn)
}

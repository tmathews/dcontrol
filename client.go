package main

import (
	"crypto/tls"

	arc "github.com/tmathews/arcnet"
)

func HandleClientConn(conn *tls.Conn, target, filename string, ignored []string) error {
	err := arc.Command(conn, CommandDEPLOY, target)
	if err != nil {
		return err
	}

	sw := arc.NewStreamWriter(conn)
	err = PackTar(filename, sw, ignored)
	sw.Terminate()
	if err != nil {
		return err
	}
	return arc.ReadStatus(conn)
}

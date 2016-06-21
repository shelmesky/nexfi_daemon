package main

import (
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

type Client struct {
	MACID  string
	Uptime string
}

func HandleConnection(conn net.Conn) {
	decoder := gob.NewDecoder(conn)
	for {
		client := new(Client)
		err := decoder.Decode(client)
		if err == io.EOF {
			log.Println("connection close")
			conn.Close()
			break
		}
		if err != nil {
			log.Println("decode network data failed:", err)
			break
		}
		log.Println("got client data:", client)
	}
}

func main() {
	if len(os.Args) <= 1 {
		log.Println("need server address argument.")
		return
	}

	log.Println("Start server")

	listen_addr := fmt.Sprintf("0.0.0.0:%s", os.Args[1])
	listen_sock, err := net.Listen("tcp", listen_addr)
	if err != nil {
		log.Println("can not listen for tcp:", err)
		return
	}
	for {
		conn, err := listen_sock.Accept()
		if err != nil {
			continue
		}
		go HandleConnection(conn)
	}
}

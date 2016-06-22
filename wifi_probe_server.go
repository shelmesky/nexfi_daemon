package main

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"log"
	"net"
	"os"
	"time"
)

var (
	db *sql.DB
)

type Client struct {
	Addr   string
	RSSI   int
	SSID   string
	Action int
}

func (this *Client) Insert() {
	stmtIns, err := db.Prepare("INSERT INTO clients VALUES(?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Println("can not do db.Prepare:", err)
		return
	}
	defer stmtIns.Close()

	now_timestamp := time.Now().Unix()
	now_timestring := time.Now().Format("2006-01-02 15:04:05")
	_, err = stmtIns.Exec(nil, this.Addr, this.RSSI, this.SSID, this.Action, now_timestamp, now_timestring)
	if err != nil {
		log.Println("can not do stmt.Exec:", err)
	}
}

func init() {
	var err error

	db, err = sql.Open("mysql", "root:4974481@tcp(121.199.74.47:3306)/wifi_probe")
	if err != nil {
		log.Println("failed connect to mysql:", err)
		os.Exit(1)
	}

	err = db.Ping()
	if err != nil {
		log.Println("failed ping mysql server:", err)
		os.Exit(1)
	}
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
		client.Insert()
	}
}

func main() {
	if len(os.Args) <= 1 {
		log.Println("need listen address argument.")
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

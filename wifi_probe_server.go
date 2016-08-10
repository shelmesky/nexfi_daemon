package main

import (
	"database/sql"
	"encoding/gob"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	db *sql.DB

	mysql_username string
	mysql_password string
	mysql_host     string
	mysql_port     int
	mysql_database string
	mysql_table    string

	listen_addr string

	client_pool *sync.Pool
)

type Client struct {
	NodeID string
	Addr   string
	Model  string
	RSSI   int
	SSID   string
	Action int
}

func init() {
	flag.StringVar(&mysql_username, "mysql_username", "root", "mysql server username")
	flag.StringVar(&mysql_password, "mysql_password", "", "mysql server password")
	flag.StringVar(&mysql_host, "mysql_host", "127.0.0.1", "mysql server hostname")
	flag.IntVar(&mysql_port, "mysql_port", 3306, "mysql server port")
	flag.StringVar(&mysql_database, "mysql_database", "wifi_probe", "mysql server database name")
	flag.StringVar(&mysql_table, "mysql_table", "mysql", "mysql server table name")

	flag.StringVar(&listen_addr, "listen_addr", "0.0.0.0:15076", "server listen host and port")

	client_pool = &sync.Pool{
		New: func() interface{} {
			return new(Client)
		},
	}
}

func (this *Client) Insert(table_name string) {
	sql := fmt.Sprintf("INSERT INTO %s VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", table_name)
	stmtIns, err := db.Prepare(sql)
	if err != nil {
		log.Println("can not do db.Prepare:", err)
		log.Println("reconnect to mysql")
		ConnectMysql()
		return
	}
	defer stmtIns.Close()

	now_timestamp := time.Now().Unix()
	now_timestring := time.Now().Format("2006-01-02 15:04:05")
	_, err = stmtIns.Exec(nil, this.NodeID, this.Addr, this.Model, this.RSSI, this.SSID, this.Action,
		now_timestamp, now_timestring)
	if err != nil {
		log.Println("can not do stmt.Exec:", err)
		log.Println("reconnect to mysql")
		ConnectMysql()
	}
}

func ConnectMysql() {
	var err error

	host_info := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", mysql_username, mysql_password,
		mysql_host, mysql_port, mysql_database)

	db, err = sql.Open("mysql", host_info)
	if err != nil {
		log.Println("failed connect to mysql:", err)
		return
	}

	err = db.Ping()
	if err != nil {
		log.Println("failed ping mysql server:", err)
		return
	}
}

func HandleConnection(conn net.Conn) {
	decoder := gob.NewDecoder(conn)
	for {
		client := client_pool.Get().(*Client)
		err := decoder.Decode(client)
		if err == io.EOF {
			log.Println("connection close")
			conn.Close()
			break
		}
		if err != nil {
			log.Println("decode network data failed:", err)
			conn.Close()
			break
		}
		log.Println("got client data:", client)
		client.Insert(mysql_table)
		client_pool.Put(client)
	}
}

func CheckFlags() {
	flag.Parse()
}

func main() {
	log.Println("Start server")

	CheckFlags()
	ConnectMysql()

	listen_sock, err := net.Listen("tcp", listen_addr)
	if err != nil {
		log.Println("can not listen for tcp:", err)
		return
	}
	log.Println("Server listen:", listen_addr)

	for {
		conn, err := listen_sock.Accept()
		if err != nil {
			continue
		}
		go HandleConnection(conn)
	}
}

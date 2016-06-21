package main

import (
	"encoding/gob"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

type Client struct {
	MACID  string
	Uptime string
}

const (
	MAC_ADDRESS_PATH = "/sys/devices/platform/ar933x_wmac/net/wlan0/phy80211/macaddress"
	UPTIME_PATH      = "/proc/uptime"
)

func ReadFileContent(filename string) (content string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	content = string(data)
	return
}

func main() {
	if len(os.Args) <= 1 {
		log.Println("need server address argument.")
		return
	}

	timeout := time.Duration(time.Second * 3)
	conn, err := net.DialTimeout("tcp", os.Args[1], timeout)
	if err != nil {
		log.Println("can not connect to server:", err)
		return
	}

	encoder := gob.NewEncoder(conn)
	mac := ReadFileContent(MAC_ADDRESS_PATH)
	uptime := ReadFileContent(UPTIME_PATH)
	//mac := "123123132"
	//uptime := "12731792387"
	encoder.Encode(&Client{mac, uptime})
	conn.Close()
}

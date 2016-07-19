// +build linux

package main

import (
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	MAC_ADDR_EXPIRE   = 60
	DEBUG             = false
	ENABLE_HTTP_SNIFF = false
)

type Client struct {
	Addr   string
	RSSI   int
	SSID   string
	Action int
}

func NewClient(addr string, rssi int, ssid string, action int) *Client {
	return &Client{addr, rssi, ssid, action}
}

type macaddr struct {
	Addr       string
	Lastupdate int64
}

var (
	monitor_interface string
	server_address    string
	mac_map           map[string]*macaddr
	map_lock          *sync.Mutex
	encoder           *gob.Encoder
	client_channel    chan *Client
	server_conn       net.Conn
)

type afpacket struct {
	ifce       *net.Interface
	fd         int
	sockaddrLL *syscall.SockaddrLinklayer
}

func init() {
	flag.StringVar(&monitor_interface, "i", "", "Network interface name to monitor")
	flag.StringVar(&server_address, "s", "", "http server address")

	mac_map = make(map[string]*macaddr, 128)
	map_lock = new(sync.Mutex)
	client_channel = make(chan *Client, 1024)
}

func ConnectServer() {
	var err error

	if server_conn != nil {
		server_conn.Close()
	}

	server_conn, err = net.DialTimeout("tcp", server_address, 3*time.Second)
	if err != nil {
		log.Println("failed connect to server:", err)
		return
	}
	encoder = gob.NewEncoder(server_conn)
}

func CheckFlags() {
	flag.Parse()

	if monitor_interface == "" {
		fmt.Println("need network interface name")
		goto EXIT
	}

	if server_address == "" {
		fmt.Println("need server address")
		goto EXIT
	}

	return

EXIT:
	os.Exit(1)
}

func htons(h int) (n int) {
	a := uint16(42)
	if *(*byte)(unsafe.Pointer(&a)) == 42 { // little-endian
		a = uint16(h)
		n = int(a>>8 | a<<8)
	} else { // big-endian
		n = h
	}
	return
}

func newDev(ifce *net.Interface) (*afpacket, error) {
	var err error

	d := new(afpacket)
	d.ifce = ifce

	d.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(0x0003))
	if err != nil {
		return d, err
	}

	d.sockaddrLL = new(syscall.SockaddrLinklayer)
	d.sockaddrLL.Ifindex = ifce.Index
	d.sockaddrLL.Protocol = uint16(htons(0x0003))
	syscall.Bind(d.fd, d.sockaddrLL)

	return d, err
}

func (d *afpacket) Interface() *net.Interface {
	return d.ifce
}

func (d *afpacket) Close() error {
	return syscall.Close(d.fd)
}

func (d *afpacket) Read(to []byte) error {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
			debug.PrintStack()
		}
	}()

	_, _, err := syscall.Recvfrom(d.fd, to, 0)
	if err != nil {
		return err
	}
	return nil
}

func ClientSender() {
	ConnectServer()

	for {
		if encoder != nil {
			client := <-client_channel
			err := encoder.Encode(client)
			if err != nil {
				log.Println("send data to server failed:", err)
				ConnectServer()
			}
		} else {
			time.Sleep(1 * time.Second)
			ConnectServer()
		}
	}
}

func CheckExipreMAC() {
	for {

		map_lock.Lock()
		for mac_str, mac_client := range mac_map {
			now := time.Now().Unix()
			if now-mac_client.Lastupdate > MAC_ADDR_EXPIRE {
				delete(mac_map, mac_str)
				if DEBUG {
					log.Printf("MAC: %s has left\n", mac_str)
				}
				client_channel <- NewClient(mac_client.Addr, 0, "", 2)
			}
		}
		map_lock.Unlock()

		time.Sleep(5 * time.Second)
	}
}

func HandleFrame(frame []byte) {
	lens := int(frame[2])
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
			debug.PrintStack()
		}
	}()

	// beacon frame
	/*
		if frame[lens] == 0x80 {
			mac := frame[lens+10 : lens+16]
			ssid := frame[lens+38 : (lens + 38 + int(frame[lens+37]))]
			mac_str := fmt.Sprintf("%x:%x:%x:%x:%x:%x", int(mac[0]), int(mac[1]), int(mac[2]), int(mac[3]), int(mac[4]), int(mac[5]))
			ssid_str := string(ssid)
			fmt.Printf("MAC: %s, SSID: %s\n", mac_str, ssid_str)
		}
	*/

	// probe request frame
	if frame[lens] == 0x40 {
		mac := frame[lens+10 : lens+16]
		ssid := frame[lens+26 : (lens + 26 + int(frame[lens+25]))]
		ssi_signal := 256 - int(frame[30])
		mac_str := fmt.Sprintf("%x:%x:%x:%x:%x:%x", int(mac[0]), int(mac[1]), int(mac[2]), int(mac[3]), int(mac[4]), int(mac[5]))
		ssid_str := string(ssid)
		if DEBUG {
			fmt.Printf("MAC: %s, SSID: %s SSI: -%d\n", mac_str, ssid_str, ssi_signal)
		}

		now := time.Now().Unix()

		map_lock.Lock()
		defer map_lock.Unlock()

		mac_client, ok := mac_map[mac_str]
		if ok == true {
			mac_client.Lastupdate = now
		} else {
			mac_client := new(macaddr)
			mac_client.Addr = mac_str
			mac_client.Lastupdate = time.Now().Unix()
			mac_map[mac_str] = mac_client
			if DEBUG {
				log.Printf("MAC: %s has join\n", mac_str)
			}
			client_channel <- NewClient(mac_str, ssi_signal, ssid_str, 1)
		}
	}

	// plain http request
	if frame[lens] == 0x88 && ENABLE_HTTP_SNIFF {
		qos_data_frame := 26
		llc_frame_start := lens + qos_data_frame

		// llc frame
		if frame[llc_frame_start] == 0xaa && frame[llc_frame_start+1] == 0xaa {

			// ip frame
			if frame[llc_frame_start+6] == 0x08 && frame[llc_frame_start+7] == 0x00 {

				llc_frame := 8
				ip_frame_start := lens + qos_data_frame + llc_frame

				// ip frame is version 4 and head length is 20 bytes
				if frame[ip_frame_start] == 0x45 {

					// ip frame contains tcp frame
					if frame[ip_frame_start+9] == 0x06 {

						// payload size with tcp and data
						ip_frame_payload := frame[ip_frame_start+2 : ip_frame_start+4]
						ip_frame_payload_size := uint16(binary.BigEndian.Uint16(ip_frame_payload))

						// ip frame head size
						ip_frame_head_lens := int(frame[ip_frame_start] & 0x0F)

						tcp_frame_start := ip_frame_start + (ip_frame_head_lens * 4)
						http_frame_start := tcp_frame_start + 32

						//log.Printf("%x\n", frame[tcp_frame_start+12])

						//http get request
						if frame[http_frame_start] == 0x47 &&
							frame[http_frame_start+1] == 0x45 &&
							frame[http_frame_start+2] == 0x54 {

							http_frame_size := int(ip_frame_payload_size - 32 - 20)
							log.Printf("%s\n", frame[http_frame_start:http_frame_start+http_frame_size])
						}
					}
				}
			}
		}
	}
}

func main() {
	CheckFlags()

	iface, err := net.InterfaceByName(monitor_interface)
	if err != nil {
		log.Println(err)
		return
	}

	dev, err := newDev(iface)
	if err != nil {
		log.Println(err)
		return
	}

	go CheckExipreMAC()
	go ClientSender()

	frame := make([]byte, 1500)
	for {
		err := dev.Read(frame)
		if err != nil {
			log.Println(err)
			continue
		}
		HandleFrame(frame)
	}
}

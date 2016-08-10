// +build linux

package main

import (
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	MAC_ADDR_EXPIRE      = 60
	DEBUG                = true
	ENABLE_HTTP_SNIFF    = true
	ENABLE_BEACON_FRAME  = false
	ENABLE_PROBE_REQUEST = false
	MAC_ADDRESS_PATH     = "/sys/devices/platform/ar933x_wmac/net/wlan0/phy80211/macaddress"
)

var (
	NODE_ID string
	Log     = log.New(os.Stdout, "Prober: ", log.Ldate|log.Ltime|log.Lshortfile)
)

type Client struct {
	NodeID string
	Addr   string
	Model  string
	RSSI   int
	SSID   string
	Action int
}

func NewClient(addr string, rssi int, ssid string, action int) *Client {
	client_model_map_lock.RLock()
	defer client_model_map_lock.RUnlock()

	client := client_pool.Get().(*Client)

	if model, ok := client_model_map[addr]; ok {
		client.Model = model
	} else {
		client.Model = ""
	}
	return client
}

type macaddr struct {
	Addr       string
	Lastupdate int64
}

var (
	monitor_interface     string
	server_address        string
	mac_map               map[string]*macaddr
	map_lock              *sync.Mutex
	encoder               *gob.Encoder
	client_channel        chan *Client
	server_conn           net.Conn
	client_model_map      map[string]string
	client_model_map_lock *sync.RWMutex
	client_pool           *sync.Pool
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

	client_pool = &sync.Pool{
		New: func() interface{} {
			return new(Client)
		},
	}

	client_model_map = make(map[string]string, 128)
	client_model_map_lock = new(sync.RWMutex)

	NODE_ID = ReadNodeID()
}

func ReadNodeID() (ret string) {
	data, err := ioutil.ReadFile(MAC_ADDRESS_PATH)
	if err != nil {
		Log.Println("read mac address failed:", err)
		return
	}

	return strings.Trim(string(data), "\n")
}

func ConnectServer() {
	var err error

	if server_conn != nil {
		server_conn.Close()
	}

	server_conn, err = net.DialTimeout("tcp", server_address, 3*time.Second)
	if err != nil {
		Log.Println("failed connect to server:", err)
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
			Log.Println(err)
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
				Log.Println("send data to server failed:", err)
				ConnectServer()
			}
			client_pool.Put(client)
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
					Log.Printf("MAC: %s has left\n", mac_str)
				}
				client_channel <- NewClient(mac_client.Addr, 0, "", 2)
			}
		}
		map_lock.Unlock()

		time.Sleep(5 * time.Second)
	}
}

func UpdateClientBrower(mac_str, browser_agent string) {
	client_model_map_lock.Lock()
	defer client_model_map_lock.Unlock()

	if strings.Contains(browser_agent, "iPhone") {
		client_model_map[mac_str] = "iPhone"
	}
}

func HandleFrame(frame []byte) {
	lens := int(frame[2])
	defer func() {
		if err := recover(); err != nil {
			Log.Println(err)
			debug.PrintStack()
		}
	}()

	// beacon frame
	if frame[lens] == 0x80 && ENABLE_BEACON_FRAME {
		mac := frame[lens+10 : lens+16]
		ssid := frame[lens+38 : (lens + 38 + int(frame[lens+37]))]
		mac_str := fmt.Sprintf("%x:%x:%x:%x:%x:%x", int(mac[0]), int(mac[1]), int(mac[2]), int(mac[3]), int(mac[4]), int(mac[5]))
		ssid_str := string(ssid)
		fmt.Printf("MAC: %s, SSID: %s\n", mac_str, ssid_str)
	}

	// probe request frame
	if frame[lens] == 0x40 && ENABLE_PROBE_REQUEST {
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
				Log.Printf("MAC: %s has join\n", mac_str)
			}
			client_channel <- NewClient(mac_str, ssi_signal, ssid_str, 1)
		}
	}

	// plain http request
	if frame[lens] == 0x88 && ENABLE_HTTP_SNIFF {
		mac := frame[lens+10 : lens+16]
		mac_str := fmt.Sprintf("%x:%x:%x:%x:%x:%x", int(mac[0]), int(mac[1]), int(mac[2]), int(mac[3]), int(mac[4]), int(mac[5]))

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

						//Log.Printf("%x\n", frame[tcp_frame_start+12])

						//http get request
						if frame[http_frame_start] == 0x47 &&
							frame[http_frame_start+1] == 0x45 &&
							frame[http_frame_start+2] == 0x54 &&
							// if packet size of ip frame paylod is more than 1024
							// or less than 64, we ignore it.
							ip_frame_payload_size < 1024 &&
							ip_frame_payload_size > 64 {

							http_frame_size := int(ip_frame_payload_size - 32 - 20)
							http_head := strings.Split(string(frame[http_frame_start:http_frame_start+http_frame_size]), "\r\n")
							for idx := range http_head {
								http_head_item := http_head[idx]
								if strings.HasPrefix(http_head_item, "User-Agent") {
									UpdateClientBrower(mac_str, http_head_item)
								}
							}
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
		Log.Println(err)
		return
	}

	dev, err := newDev(iface)
	if err != nil {
		Log.Println(err)
		return
	}

	go CheckExipreMAC()
	go ClientSender()

	frame := make([]byte, 1500)
	for {
		err := dev.Read(frame)
		if err != nil {
			Log.Println(err)
			continue
		}
		HandleFrame(frame)
	}
}

// +build linux

package main

import (
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	MAC_ADDR_EXPIRE      = 30
	DEBUG                = true
	ENABLE_HTTP_SNIFF    = false
	ENABLE_BEACON_FRAME  = false
	ENABLE_PROBE_REQUEST = true
	MAC_ADDRESS_PATH     = "/sys/devices/platform/ar933x_wmac/net/wlan0/phy80211/macaddress"
	LOCAL_HTTP_SERVER    = "0.0.0.0:8080"
)

var (
	NODE_ID            string
	Log                = log.New(os.Stdout, "Prober: ", log.Ldate|log.Ltime|log.Lshortfile)
	wheel_milliseconds = NewTimingWheel(10*time.Millisecond, 2)
)

type Client struct {
	NodeID string `json:"node_id"`
	Addr   string `json:"mac_addr"`
	From   string `json:"from"`
	Model  string `json:"model"`
	RSSI   int    `json:"rssi"`
	SSID   string `json:"ssid"`
	Action int    `json:"action"`
}

type TimingWheel struct {
	sync.Mutex
	interval   time.Duration
	ticker     *time.Ticker
	quit       chan struct{}
	maxTimeout time.Duration
	cs         []chan struct{}
	pos        int
}

func NewTimingWheel(interval time.Duration, buckets int) *TimingWheel {
	w := new(TimingWheel)

	w.interval = interval
	w.quit = make(chan struct{})
	w.pos = 0
	w.maxTimeout = time.Duration(interval * (time.Duration(buckets)))
	w.cs = make([]chan struct{}, buckets)

	for i := range w.cs {
		w.cs[i] = make(chan struct{})
	}

	w.ticker = time.NewTicker(interval)
	go w.run()

	return w
}

func (w *TimingWheel) Stop() {
	close(w.quit)
}

func (w *TimingWheel) After(timeout time.Duration) <-chan struct{} {
	if timeout >= w.maxTimeout {
		panic("timeout too much, over maxtimeout")
	}

	w.Lock()
	index := (w.pos + int(timeout/w.interval)) % len(w.cs)
	b := w.cs[index]
	w.Unlock()

	return b
}

func (w *TimingWheel) run() {
	for {
		select {
		case <-w.ticker.C:
			w.onTicker()
		case <-w.quit:
			w.ticker.Stop()
			return
		}
	}
}

func (w *TimingWheel) onTicker() {
	w.Lock()
	lastC := w.cs[w.pos]
	w.cs[w.pos] = make(chan struct{})
	w.pos = (w.pos + 1) % len(w.cs)
	w.Unlock()

	close(lastC)
}

func NewClient(addr string, from string, rssi int, ssid string, action int) *Client {
	client_model_map_lock.RLock()

	//client := client_pool.Get().(*Client)
	client := new(Client)

	client.NodeID = NODE_ID
	client.Addr = addr
	client.From = from
	client.RSSI = rssi
	client.SSID = ssid
	client.Action = action

	if model, ok := client_model_map[addr]; ok {
		client.Model = model
	} else {
		client.Model = ""
	}
	client_model_map_lock.RUnlock()
	return client
}

type macaddr struct {
	Addr       string
	Lastupdate int64
}

var (
	monitor_interface     string
	server_address        string
	start_http_server     bool
	start_remote_send     bool
	mac_map               map[string]*macaddr
	map_lock              *sync.Mutex
	client_channel        chan *Client
	server_conn           net.Conn
	client_model_map      map[string]string
	client_model_map_lock *sync.RWMutex
	//client_pool           *sync.Pool
	http_queue chan *Client
)

type afpacket struct {
	ifce       *net.Interface
	fd         int
	sockaddrLL *syscall.SockaddrLinklayer
}

func init() {
	flag.StringVar(&monitor_interface, "i", "", "Network interface name to monitor")
	flag.StringVar(&server_address, "s", "", "http server address")
	flag.BoolVar(&start_http_server, "http", false, "start local http server")
	flag.BoolVar(&start_remote_send, "send", false, "send data to remote server")

	mac_map = make(map[string]*macaddr, 128)
	map_lock = new(sync.Mutex)
	client_channel = make(chan *Client, 1024)

	/*
		client_pool = &sync.Pool{
			New: func() interface{} {
				return new(Client)
			},
		}
	*/

	client_model_map = make(map[string]string, 128)
	client_model_map_lock = new(sync.RWMutex)

	http_queue = make(chan *Client, 1024)

	NODE_ID = ReadNodeID()
}

func ReadNodeID() (ret string) {
	data, err := ioutil.ReadFile(MAC_ADDRESS_PATH)
	if err != nil {
		Log.Println(err)
		return
	}

	return strings.Trim(string(data), "\n")
}

func ConnectServer() *gob.Encoder {
	var err error

	if server_conn != nil {
		server_conn.Close()
		server_conn = nil
	}

	server_conn, err = net.DialTimeout("tcp", server_address, 3*time.Second)
	if err != nil {
		Log.Println("failed connect to server:", err)
		return nil
	}
	return gob.NewEncoder(server_conn)
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

func ClientSender() {
	encoder := ConnectServer()

	for {
		if encoder != nil {
			client := <-client_channel
			if DEBUG {
				Log.Printf("go client: %v\n", client)
			}
			err := encoder.Encode(client)
			if err != nil {
				Log.Println("send data to server failed:", err)
				encoder = ConnectServer()
			}
			//client_pool.Put(client)
		} else {
			time.Sleep(1 * time.Second)
			encoder = ConnectServer()
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
				if start_remote_send {
					client_channel <- NewClient(mac_client.Addr, "leave", 0, "", 2)
				}
			}
		}
		map_lock.Unlock()

		time.Sleep(5 * time.Second)
	}
}

func HandleProbeReq(buffer string) {
	station_list := strings.Split(buffer, "\n")

	map_lock.Lock()

	if len(station_list) > 1 {
		for idx := range station_list {
			station := station_list[idx]
			station_property := strings.Split(station, ",")
			if len(station_property) > 1 {
				mac_addr := station_property[0]
				RSSI := station_property[1]
				RSSI_int64, err := strconv.ParseInt(RSSI, 10, 32)
				if err != nil {
					Log.Println("convert RSSI to int failed:", err)
				}
				SSID := station_property[2]

				now := time.Now().Unix()

				mac_client, ok := mac_map[mac_addr]
				if ok == true {
					mac_client.Lastupdate = now
				} else {
					mac_client := new(macaddr)
					mac_client.Addr = mac_addr
					mac_client.Lastupdate = time.Now().Unix()
					mac_map[mac_addr] = mac_client

					if DEBUG {
						Log.Printf("MAC: %s has join\n", mac_addr)
					}

					if start_remote_send == true {
						client := NewClient(mac_addr, "probe", int(RSSI_int64), SSID, 1)
						client_channel <- client
					}
				}
			}
		}
	}
	map_lock.Unlock()
}

func APIHandler(w http.ResponseWriter, r *http.Request) {
	client := <-http_queue
	data, err := json.Marshal(client)
	if err != nil {
		Log.Println("json marshal failed:", err)
	}
	//client_pool.Put(client)
	w.Write(data)
}

func main() {
	CheckFlags()

	if start_remote_send == true {
		go CheckExipreMAC()
		go ClientSender()
	}

	buffer := make([]byte, 4096)
	for {
		time.Sleep(time.Second * 1)

		f, err := os.Open("/proc/nexfi_proc")
		if err != nil {
			Log.Println("Open proc file failed:", err)
			continue
		}

		n, err := f.Read(buffer)
		if err != nil && err != io.EOF {
			Log.Println("Read proc file failed:", err)
			continue
		}

		if n > 0 {
			HandleProbeReq(string(buffer[:n]))
		}
	}
}

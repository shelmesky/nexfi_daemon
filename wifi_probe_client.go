// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
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
	MAC_ADDRESS_PATH     = "/sys/class/net/ra0/address"
	LOCAL_HTTP_SERVER    = "0.0.0.0:8080"

	// BlockSize is the size of a TEA block, in bytes.
	BlockSize = 8

	// KeySize is the size of a TEA key, in bytes.
	KeySize = 16

	// delta is the TEA key schedule constant.
	delta = 0x9e3779b9

	// numRounds is the standard number of rounds in TEA.
	numRounds = 32

	Debug = false
)

var (
	NODE_ID            string
	Log                = log.New(os.Stdout, "Prober: ", log.Ldate|log.Ltime|log.Lshortfile)
	wheel_milliseconds = NewTimingWheel(10*time.Millisecond, 2)
)

// tea is an instance of the TEA cipher with a particular key.
type tea struct {
	key    [16]byte
	rounds int
}

type StationData_Head struct {
	Start_sign        byte    //开始标志
	Major_version     [2]byte //主版本号
	Sub_version       [2]byte //子版本号
	Primary_command   [2]byte //主命令标志
	Secondary_command [2]byte //子命令标志
	Encrypt_type      byte    //加密类型
	Data_length       [4]byte //发送数据长度
	Encrypted_padding byte    //填充的字节数
}

type StationData_Body struct {
	Timedate         [20]byte //事件发生时间
	Station_mac_addr [6]byte  //用户MAC地址
	Prober_mac_addr  [6]byte  //探针MAC地址
	Station_rssi     [8]byte  //场强
	Longtitude       [12]byte //经度
	Latitude         [12]byte //纬度
	Reverse_field_1  [32]byte //保留字段1
	Reverse_field_2  [32]byte //保留字段2
	Reverse_field_3  [4]byte  //保留字段3
	Reverse_field_4  [4]byte  //保留字段4
}

type StationData_Tail struct {
	CRC32    [4]byte //包头和包体的CRC32值
	End_sign byte    //结束标志
}

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

// NewCipher returns an instance of the TEA cipher with the standard number of
// rounds. The key argument must be 16 bytes long.
func NewCipher(key []byte) (*tea, error) {
	return NewCipherWithRounds(key, numRounds)
}

// NewCipherWithRounds returns an instance of the TEA cipher with a given
// number of rounds, which must be even. The key argument must be 16 bytes
// long.
func NewCipherWithRounds(key []byte, rounds int) (*tea, error) {
	if len(key) != 16 {
		return nil, errors.New("tea: incorrect key size")
	}

	if rounds&1 != 0 {
		return nil, errors.New("tea: odd number of rounds specified")
	}

	c := &tea{
		rounds: rounds,
	}
	copy(c.key[:], key)

	return c, nil
}

// BlockSize returns the TEA block size, which is eight bytes. It is necessary
// to satisfy the Block interface in the package "crypto/cipher".
func (*tea) BlockSize() int {
	return BlockSize
}

// Encrypt encrypts the 8 byte buffer src using the key in t and stores the
// result in dst. Note that for amounts of data larger than a block, it is not
// safe to just call Encrypt on successive blocks; instead, use an encryption
// mode like CBC (see crypto/cipher/cbc.go).

func (t *tea) EncryptBytes(dst, src []byte) {
	var iRound int
	src_len := len(src)
	if src_len%8 == 0 {
		iRound = src_len / 8
	} else {
		iRound = src_len/8 + 1
	}
	if Debug {
		Log.Printf("EncryptString: src_len: %d iRound: %d\n", src_len, iRound)
	}
	for i := 0; (iRound - 1) > i; i++ {
		iPos := i * 8
		idst := dst[iPos : iPos+8]
		isrc := src[iPos : iPos+8]
		if Debug {
			Log.Printf("EncryptString: iPos: %d\n", iPos)
			Log.Printf("EncryptString: idst_len: %d, isrc_len: %d\n", len(idst), len(isrc))
		}
		t.Encrypt(idst, isrc)
	}
}

func (t *tea) Encrypt(dst, src []byte) {
	e := binary.LittleEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	k0, k1, k2, k3 := e.Uint32(t.key[0:]), e.Uint32(t.key[4:]), e.Uint32(t.key[8:]), e.Uint32(t.key[12:])

	if Debug {
		Log.Printf("%d %d %d %d %d %d\n", v0, v1, k0, k1, k2, k3)
	}

	sum := uint32(0)
	delta := uint32(delta)

	for i := 0; i < t.rounds; i++ {
		sum += delta
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
	if Debug {
		Log.Printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst[6], dst[7])
	}
}

func (t *tea) DecryptBytes(dst, src []byte) error {
	var iRound int

	dst_len := len(dst)
	src_len := len(src)

	if dst_len < src_len {
		Log.Printf("DecryptString: dst_len < src_len, %d < %d\n", dst_len, src_len)
		return fmt.Errorf("dst_len < src_len\n")
	}

	if src_len%8 != 0 {
		Log.Printf("src_len不能被8整除: %d\n", src_len)
	}

	dst_len = src_len

	if src_len%8 == 0 {
		iRound = src_len / 8
	} else {
		iRound = src_len/8 + 1
	}

	for i := 0; (iRound - 1) > i; i++ {
		iPos := i * 8
		idst := dst[iPos : iPos+8]
		isrc := src[iPos : iPos+8]
		if Debug {
			Log.Printf("DecryptString: iPos: %d\n", iPos)
			Log.Printf("DecryptString: idst_len: %d, isrc_len: %d\n", len(idst), len(isrc))
		}
		t.Decrypt(idst, isrc)
	}

	return nil
}

// Decrypt decrypts the 8 byte buffer src using the key in t and stores the
// result in dst.
func (t *tea) Decrypt(dst, src []byte) {
	var sum uint32
	e := binary.LittleEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	k0, k1, k2, k3 := e.Uint32(t.key[0:]), e.Uint32(t.key[4:]), e.Uint32(t.key[8:]), e.Uint32(t.key[12:])

	delta := uint32(delta)
	//sum := delta * uint32(t.rounds/2) // in general, sum = delta * n
	if t.rounds == 32 {
		sum = uint32(0xC6EF3720)
	} else if t.rounds == 16 {
		sum = uint32(0xE3779B90)
	}

	for i := 0; i < t.rounds; i++ {
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		sum -= delta
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
}

func MacStringToBytes(mac_address string) []byte {
	var mac_string string
	address_splited := strings.Split(mac_address, ":")
	for idx := range address_splited {
		mac_string += address_splited[idx]
	}

	src := []byte(mac_string)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		fmt.Println(err)
	}
	return dst
}

func SendToServer(time_str, prober_mac, station_mac, rssi string) {
	//mac := MacStringToBytes("00:03:7f:c2:00:43")
	//fmt.Printf("%02x %02x %02x %02x %02x %02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])

	key_bytes := []byte{0x3A, 0xDA, 0x75, 0x21, 0xDB, 0xE2, 0xDB, 0xB3, 0x11, 0xB4, 0x49, 0x01, 0xA5, 0xC6, 0xEA, 0xD4}
	block, err := NewCipher(key_bytes)
	if err != nil {
		Log.Println(err)
	}

	var bin_buf_head bytes.Buffer
	var bin_buf_body bytes.Buffer
	var bin_buf_tail bytes.Buffer

	station_data_head := StationData_Head{}
	station_data_body := StationData_Body{}
	station_data_tail := StationData_Tail{}

	station_data_head.Start_sign = 0x4E
	station_data_head.Major_version = [2]byte{0x00, 0x01}
	station_data_head.Sub_version = [2]byte{0x00, 0x01}
	station_data_head.Primary_command = [2]byte{0x00, 0x02}
	station_data_head.Encrypt_type = 0x01
	copy(station_data_head.Data_length[:], UInt32ToBytes(151))
	station_data_head.Encrypted_padding = 136

	//copy(station_data_body.Timedate[:], "2016-09-02 12:12:12")
	copy(station_data_body.Timedate[:], time_str)
	//copy(station_data_body.Station_mac_addr[:], MacStringToBytes("00:03:7f:c2:00:43"))
	//copy(station_data_body.Prober_mac_addr[:], MacStringToBytes("c8:5b:76:3b:40:1d"))
	copy(station_data_body.Station_mac_addr[:], MacStringToBytes(station_mac))
	copy(station_data_body.Prober_mac_addr[:], MacStringToBytes(prober_mac))
	//copy(station_data_body.Station_rssi[:], "85")
	copy(station_data_body.Station_rssi[:], rssi)
	copy(station_data_body.Longtitude[:], "111.111111")
	copy(station_data_body.Latitude[:], "111.111111")

	binary.Write(&bin_buf_head, binary.LittleEndian, station_data_head)
	binary.Write(&bin_buf_body, binary.LittleEndian, station_data_body)

	body_bytes := bin_buf_body.Bytes()
	head_bytes := bin_buf_head.Bytes()

	encrypted_body_bytes := make([]byte, bin_buf_body.Len())
	block.EncryptBytes(encrypted_body_bytes, body_bytes)
	if Debug {
		log.Printf("### body_bytes: %s\n", string(encrypted_body_bytes))
	}

	head_body_buf := make([]byte, len(head_bytes)+len(encrypted_body_bytes))
	copy(head_body_buf, head_bytes)
	copy(head_body_buf[len(head_bytes):], encrypted_body_bytes)
	//copy(head_body_buf[len(head_bytes):], body_bytes)

	ieee_crc32q := crc32.MakeTable(crc32.IEEE)
	if Debug {
		//fmt.Printf("CRC32: 0x%08x\n", crc32.Checksum(head_body_buf, ieee_crc32q))
	}
	head_body_crc32 := crc32.Checksum(head_body_buf, ieee_crc32q)

	copy(station_data_tail.CRC32[:], UInt32ToBytes(head_body_crc32))
	station_data_tail.End_sign = 0x47

	binary.Write(&bin_buf_tail, binary.LittleEndian, station_data_tail)
	head_body_tail_buf := make([]byte, len(head_bytes)+len(encrypted_body_bytes)+bin_buf_tail.Len())
	//head_body_tail_buf := make([]byte, len(head_bytes)+len(body_bytes)+bin_buf_tail.Len())
	copy(head_body_tail_buf, head_body_buf)
	copy(head_body_tail_buf[len(head_body_buf):], bin_buf_tail.Bytes())

	if Debug {
		fmt.Printf("head struct length:\n %d\n\n", len(head_bytes))
		fmt.Printf("body struct length:\n %d\n\n", len(body_bytes))
		fmt.Printf("tail struct length:\n %d\n\n", bin_buf_tail.Len())

		fmt.Printf("head:\n%x\n\n", head_bytes)
		fmt.Printf("body:\n%x\n\n", encrypted_body_bytes)
		fmt.Printf("tail:\n%x\n\n", bin_buf_tail.Bytes())

		fmt.Printf("%x\n\n", head_body_tail_buf)
	}

	//addr, err := net.ResolveUDPAddr("udp4", "114.80.253.167:61440")
	//addr, err := net.ResolveUDPAddr("udp4", "222.186.160.115:61440")
	addr, err := net.ResolveUDPAddr("udp4", server_address)
	if err != nil {
		log.Println(err)
		return
	}

	server, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		Log.Println(err)
		return
	}

	n, err := server.Write(head_body_tail_buf)
	if err != nil {
		Log.Println(err)
	}

	Log.Printf("write %d bytes to server\n", n)
}

func UInt32ToBytes(i uint32) []byte {
	var buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
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
		return "test_node"
	}

	return strings.Trim(string(data), "\n")
}

func CheckFlags() {
	flag.Parse()

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
	for {
		client := <-client_channel
		Log.Printf("go client: %v\n", client)

		time_str := time.Now().Format("2006-01-02 15:04:05")
		prober_mac := client.NodeID
		station_mac := client.Addr
		rssi := strconv.Itoa(client.RSSI)
		SendToServer(time_str, prober_mac, station_mac, rssi)
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

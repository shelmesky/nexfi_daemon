package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var (
	MAX_PAYLOAD_SIZE int = 1024
	ETHER_TYPE           = [2]byte{0x55, 0xaa}
)

// Ethertype is a type used represent the ethertype of an ethernet frame.
// Defined as a 2-byte array, variables of this type are intended to be used as
// immutable values.
type Ethertype [2]byte

func equalMAC(a, b net.HardwareAddr) bool {
	return bytes.Equal([]byte(a), []byte(b))
}

type FrameFilter func(frame Frame) bool

// Frame represents an ethernet frame. The length of the underlying slice of a
// Frame should always reflect the ethernet frame length.
type Frame []byte

// Tagging is a type used to indicate whether/how a frame is tagged. The value
// is number of bytes taken by tagging.
type Tagging byte

// Const values for different taggings
const (
	NotTagged    Tagging = 0
	Tagged       Tagging = 4
	DoubleTagged Tagging = 8
)

// Destination returns the destination address field of the frame. The address
// references a slice on the frame.
//
// It is not safe to use this method if f is nil or an invalid ethernet frame.
func (f Frame) Destination() net.HardwareAddr {
	return net.HardwareAddr(f[:6:6])
}

// Source returns the source address field of the frame. The address references
// a slice on the frame.
//
// It is not safe to use this method if f is nil or an invalid ethernet frame.
func (f Frame) Source() net.HardwareAddr {
	return net.HardwareAddr(f[6:12:12])
}

// Tagging returns whether/how the frame has 802.1Q tag(s).
//
// It is not safe to use this method if f is nil or an invalid ethernet frame.
func (f Frame) Tagging() Tagging {
	if f[12] == 0x81 && f[13] == 0x00 {
		return Tagged
	} else if f[12] == 0x88 && f[13] == 0xa8 {
		return DoubleTagged
	}
	return NotTagged
}

// Tag returns a slice holding the tag part of the frame, if any. Note that
// this includes the Tag Protocol Identifier (TPID), e.g. 0x8100 or 0x88a8.
// Upper layer should use the returned slice for both reading and writing.
//
// It is not safe to use this method if f is nil or an invalid ethernet frame.
func (f Frame) Tags() []byte {
	tagging := f.Tagging()
	return f[12 : 12+tagging : 12+tagging]
}

// Ethertype returns the ethertype field of the frame.
//
// It is not safe to use this method if f is nil or an invalid ethernet frame.
func (f Frame) Ethertype() Ethertype {
	ethertypePos := 12 + f.Tagging()
	return Ethertype{f[ethertypePos], f[ethertypePos+1]}
}

// Payload returns a slice holding the payload part of the frame. Upper layer
// should use the returned slice for both reading and writing purposes.
//
// It is not safe to use this method if f is nil or an invalid ethernet frame.
func (f Frame) Payload() []byte {
	return f[12+f.Tagging()+2:]
}

// Resize re-slices (*f) so that len(*f) holds exactly payloadSize bytes of
// payload. If cap(*f) is not large enough, a new slice is made and content
// from old slice is copied to the new one.
//
// If len(*f) is less than 14 bytes, it is assumed to be not tagged.
//
// It is safe to call Resize on a pointer to a nil Frame.
func (f *Frame) Resize(payloadSize int) {
	tagging := NotTagged
	if len(*f) > 6+6+2 {
		tagging = f.Tagging()
	}
	f.resize(6 + 6 + int(tagging) + 2 + payloadSize)
}

// Prepare prepares *f to be used, by filling in dst/src address, setting up
// proper tagging and ethertype, and resizing it to proper length.
//
// It is safe to call Prepare on a pointer to a nil Frame or invalid Frame.
func (f *Frame) Prepare(dst net.HardwareAddr, src net.HardwareAddr, tagging Tagging, ethertype Ethertype, payloadSize int, payload []byte) {
	f.resize(6 + 6 + int(tagging) + 2 + payloadSize)
	copy((*f)[0:6:6], dst)
	copy((*f)[6:12:12], src)
	if tagging == Tagged {
		(*f)[12] = 0x81
		(*f)[13] = 0x00
	} else if tagging == DoubleTagged {
		(*f)[12] = 0x88
		(*f)[13] = 0xa8
	}
	(*f)[12+tagging] = ethertype[0]
	(*f)[12+tagging+1] = ethertype[1]
	if payload != nil {
		copy((*f)[12+tagging+2:], payload)
	}
	return
}

func (f *Frame) resize(length int) {
	if cap(*f) < length {
		old := *f
		*f = make(Frame, length, length)
		copy(*f, old)
	} else {
		*f = (*f)[:length]
	}
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

type afpacket struct {
	ifce   *net.Interface
	filter FrameFilter

	fd int

	// for outgoing frames
	sockaddrLL *syscall.SockaddrLinklayer

	// max payload size
	max_payload_size int
}

func newDev(ifce *net.Interface, frameFilter FrameFilter, max_payload_size int) (*afpacket, error) {
	var err error

	d := new(afpacket)
	d.ifce = ifce
	d.filter = frameFilter

	d.max_payload_size = max_payload_size

	d.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(syscall.ETH_P_ALL))
	if err != nil {
		return d, err
	}

	d.sockaddrLL = new(syscall.SockaddrLinklayer)
	d.sockaddrLL.Ifindex = ifce.Index
	d.sockaddrLL.Halen = 6

	return d, err
}

func (d *afpacket) Interface() *net.Interface {
	return d.ifce
}

func (d *afpacket) Close() error {
	return syscall.Close(d.fd)
}

func (d *afpacket) Write(from Frame) (err error) {
	copy(d.sockaddrLL.Addr[:6], []byte(from.Destination()))
	err = syscall.Sendto(d.fd, []byte(from), 0, d.sockaddrLL)
	if err != nil {
		return
	}
	return
}

func (d *afpacket) Read(to *Frame) (err error) {
	to.Resize(d.ifce.MTU)
	for {
		*to = (*to)[:cap(*to)]
		var n int
		n, _, err = syscall.Recvfrom(d.fd, []byte(*to), 0)
		if err != nil {
			return
		}
		*to = (*to)[:n]
		if !equalMAC(to.Source(), d.ifce.HardwareAddr) {
			if d.filter == nil || d.filter(*to) {
				if to.Ethertype() == Ethertype(ETHER_TYPE) {
					return
				}
			}
		}
	}
}

func (d *afpacket) SendFrame(dst_mac_str string, data []byte) error {
	dst_mac, err := net.ParseMAC(dst_mac_str)
	if err != nil {
		return err
	}

	data_len := len(data)
	if data_len > d.max_payload_size {
		data = data[:d.max_payload_size]
	}
	frame := new(Frame)
	ether_type := Ethertype(ETHER_TYPE)
	frame.Prepare(dst_mac, d.ifce.HardwareAddr, NotTagged, ether_type, data_len, data)
	err = d.Write(*frame)
	if err != nil {
		return err
	}
	return nil
}

func (d *afpacket) RecvFrame() (payload []byte, err error) {
	src_mac, err := net.ParseMAC("00:00:00:00:00:00")
	if err != nil {
		return payload, err
	}

	frame := new(Frame)
	ether_type := Ethertype(ETHER_TYPE)
	frame.Prepare(d.ifce.HardwareAddr, src_mac, NotTagged, ether_type, 0, nil)

	err = d.Read(frame)
	if err != nil {
		return payload, err
	}

	payload = frame.Payload()
	if len(payload) > d.max_payload_size {
		payload = payload[:d.max_payload_size]
	}

	return payload, err
}

type ProtoProxy struct {
	DesMac string //destination mac address
	NicInt string //network interface car
	DevNic *afpacket
}

func (c *ProtoProxy) SetDesMac(mac string) { c.DesMac = mac }
func (c *ProtoProxy) GetDesMac() string    { return c.DesMac }
func (c *ProtoProxy) SetNicInt(nic string) { c.NicInt = nic }
func (c *ProtoProxy) GetNicInt() string    { return c.NicInt }

func (c *ProtoProxy) Send(data []byte) error {
	return c.DevNic.SendFrame(c.DesMac, data)
}

func (c *ProtoProxy) Close() error {
	return c.DevNic.Close()
}

func (c *ProtoProxy) Open() error {
	iface, err1 := net.InterfaceByName(c.NicInt)
	if err1 != nil {
		return err1
	}

	dev, err2 := newDev(iface, nil, MAX_PAYLOAD_SIZE)
	if err2 != nil {
		return err2
	}
	c.DevNic = dev

	return err2
}

func (c *ProtoProxy) Recv() (payload []byte, err error) {
	return c.DevNic.RecvFrame()
}

func CreateProtoProxy(desmac string, nicint string) *ProtoProxy {
	return &ProtoProxy{DesMac: desmac, NicInt: nicint}
}

/* payload size don't include message header */
const (
	MAX_MSG_PAYLOAD_SEZE = 1000
)

/* message header */
type MessageHeader struct {
	MsgType   uint32 //Message type
	MsgSeq    uint16 //Message sequence number
	MsgPayLen uint16 //Message payload length
}

func (msg *MessageHeader) GetMessageHeaderLen() int   { return 8 }
func (msg *MessageHeader) SetMsgType(msgtype uint32)  { msg.MsgType = msgtype }
func (msg *MessageHeader) GetMsgType() uint32         { return msg.MsgType }
func (msg *MessageHeader) SetMsgSeq(msgseq uint16)    { msg.MsgSeq = msgseq }
func (msg *MessageHeader) GetMsgSeq() uint16          { return msg.MsgSeq }
func (msg *MessageHeader) SetPayLen(msgpaylen uint16) { msg.MsgPayLen = msgpaylen }
func (msg *MessageHeader) GetMsgPayLen() uint16       { return msg.MsgPayLen }

type Message struct {
	MessageHeader
	Payload []byte
}

func (msg *Message) GetPayload() []byte        { return msg.Payload }
func (msg *Message) SetPayload(payload []byte) { msg.Payload = payload }

func (msg *Message) Marshal() ([]byte, error) {
	return json.Marshal(msg)
}

func (msg *Message) Unmarshal(data []byte) error {
	return json.Unmarshal(data, msg)
}

/* key : the first adn the second byte are zeor
   the rest are random
*/
type SecretKey struct {
	Elem [6]byte
}

func (key *SecretKey) IsValid() bool {
	return key.Elem[0] == 0
}

func Contruct(data []byte) *SecretKey {
	key := new(SecretKey)
	for i, _ := range key.Elem {
		key.Elem[i] = data[i]
	}
	return key
}

/* Generate a random secret key */
func Generator() *SecretKey {
	key := new(SecretKey)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i, _ := range key.Elem {
		if i == 0 {
			key.Elem[i] = 0
		} else {
			key.Elem[i] = byte(r.Intn(256))
		}
	}

	return key
}

func Compare(key1 *SecretKey, key2 *SecretKey) bool {
	return key1.Elem == key2.Elem
}

func ConvToString(key *SecretKey) string {
	var str string
	for i, v := range key.Elem {
		if i < len(key.Elem)-1 {
			str += fmt.Sprintf("%02X", v) + ":"
		} else {
			str += fmt.Sprintf("%02X", v)
		}
	}
	return str
}

func Exec(name string, arg ...string) (error, string) {
	fmt.Println(name)
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return err, out.String()
}

/* Wireless Network Interface Card controler for restarting the wireless mesh network */
type WNICControler struct {
	CmdScript string
}

func (ctl *WNICControler) MeshNetworkRestart() {
	opcode := "2"
	err, out := Exec("/bin/sh", ctl.CmdScript, opcode)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(out)
}

/* Store controler for storing the secret key to file */
type StoreControler struct {
	CmdScript string
}

func (ctl *StoreControler) StoreSecretKey(bssid string, meshid string) {
	opcode := "1"
	err, out := Exec("/bin/sh", ctl.CmdScript, opcode, bssid, meshid)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(out)
}

func (ctl *StoreControler) ReadSecreKey() string {
	opcode := "0"
	err, out := Exec("/bin/sh", ctl.CmdScript, opcode)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(out)
	return out
}

/* communication pipe for button event and led message */
type PipeControler struct {
	f *os.File
}

func CreatePipeControler() *PipeControler {
	return new(PipeControler)
}

func (pipe *PipeControler) OpenPipe(filename string) (err error) {
	fmt.Println("OpenPipe: ", filename)
	pipe.f, err = os.OpenFile(filename, os.O_RDWR, 0644)
	return err
}

func (pipe *PipeControler) SendMsg(data string) error {
	_, err := pipe.f.WriteString(data + "\n")
	return err
}

func (pipe *PipeControler) RecvMsg() (string, error) {
	data := make([]byte, 1024)
	n, err := pipe.f.Read(data)
	if err != nil {
		fmt.Println("button pipe read error: ", err)
		return "", err
	}

	msg := string(data[:n-1])
	return msg, err
}

func (pipe *PipeControler) ClosePipe() {
	pipe.f.Close()
}

/* control message id */
const (
	_type_msg_sync_key = 0
)

/* guard state : client and server */
const (
	_s_normal = iota
	_s_keysync
)

/* pipe message format */
/* led type : led color : led action : time */
const (
	_msg_btn0_pressed_long      = "pressed:btn0:long"
	_msg_tbled_red_blink_on     = "tbled:red:blink:on:0"
	_msg_tbled_red_blink_off    = "tbled:red:blink:off"
	_msg_tbled_green_blink_on_1 = "tbled:green:blink:on:1"
)

const (
	_broadcast_mac_addr = "FF:FF:FF:FF:FF:FF"
)

/* configuration file for config some attr */
type Configuration struct {
	Script  string `json:"command script"`
	NicName string `json:"nic interface name"`
	MsgPipe string `json:"message pipe"`
	LedPipe string `json:"led pipe"`
}

/* setter and getter for attr */
func (c *Configuration) SetNicName(nic string)     { c.NicName = nic }
func (c *Configuration) SetScript(script string)   { c.Script = script }
func (c *Configuration) SetMsgPipe(msgpipe string) { c.MsgPipe = msgpipe }
func (c *Configuration) SetLedPipe(ledpipe string) { c.LedPipe = ledpipe }
func (c *Configuration) GetScript() string         { return c.Script }
func (c *Configuration) GetNicName() string        { return c.NicName }
func (c *Configuration) GetMsgPipe() string        { return c.MsgPipe }
func (c *Configuration) GetLedPipe() string        { return c.LedPipe }

/* strore configuration file */
func (c *Configuration) SaveConfig(filename string) error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, data, 0666)
	if err != nil {
		return err
	}
	return nil
}

/* load configuration class */
func (c *Configuration) LoadConfig(filename string) (err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(data), c)
	if err != nil {
		return err
	}
	return nil
}

/* parse argument from main */
func ArgParse() *Configuration {
	filename := flag.String("f", "", "the name of configuration file.")
	if filename == nil {
		return nil
	}

	flag.Parse()
	if flag.NFlag() != 1 {
		flag.Usage()
		return nil
	}
	config := &Configuration{}
	config.LoadConfig(*filename)

	return config
}

type IChannel interface {
	Send(data []byte) error
	Recv() (payload []byte, err error)
	Open() error
	Close() error
}

type IPipeCtrl interface {
	OpenPipe(filename string) (err error)
	SendMsg(data string) error
	RecvMsg() (string, error)
	ClosePipe()
}

type GuardServer struct {
	config *Configuration
	chtran IChannel // channel for transmission
	pipe   IPipeCtrl
	wnic   *WNICControler
	store  *StoreControler
	chsync chan int // channel for sync
	isExit bool     // is exit?
}

func (guard *GuardServer) Open() {
	guard.chsync = make(chan int, 1)
}

func (guard *GuardServer) Close() {
	guard.Stop()
	close(guard.chsync)
}

func (guard *GuardServer) Start() {
	guard.isExit = false

	// generate secret key
	key := Generator()

	// not duplicate
	localkey := guard.store.ReadSecreKey()
	for ConvToString(key) == localkey {
		key = Generator()
	}

	// construct secret key message
	msg := Message{}
	msg.SetMsgType(_type_msg_sync_key)
	msg.SetPayLen(uint16(len(key.Elem)))
	msg.SetPayload(key.Elem[:])
	var seqseed uint16 = 0

	bassid := ConvToString(key)
	meshid := "n-000000"
	// update secret key
	guard.store.StoreSecretKey(bassid, meshid)

	// restart mesh network
	guard.wnic.MeshNetworkRestart()

	// trigger led
	err := guard.pipe.SendMsg(_msg_tbled_red_blink_on)
	if err != nil {
		fmt.Println(err)
	}

	// sync secret key
	for {
		if guard.isExit {
			break
		}

		seqseed++
		msg.SetMsgSeq(seqseed)

		// marshal secret key
		payload, err := msg.Marshal()
		if err != nil {
			fmt.Println("message marshal failed.")
		}

		err = guard.chtran.Send(payload)
		if err != nil {
			fmt.Println("chproxy send key failed.")
		}

		fmt.Println("send data: ", ConvToString(key))

		time.Sleep(500 * time.Millisecond)
	}

	// turn off led
	err = guard.pipe.SendMsg(_msg_tbled_red_blink_off)
	if err != nil {
		fmt.Println(err)
	}

	guard.chsync <- 0

}

func (guard *GuardServer) Stop() {
	if !guard.isExit {
		guard.isExit = true
		<-guard.chsync
	}
}

type GuardClient struct {
	config *Configuration
	chtran IChannel // channel for transmission
	pipe   IPipeCtrl
	wnic   *WNICControler
	store  *StoreControler
	chsync chan int // channel for sync
	isExit bool     // is exit?
}

func (guard *GuardClient) Open() {
	guard.chsync = make(chan int, 1)
}

func (guard *GuardClient) Close() {
	guard.Stop()
	close(guard.chsync)
}

func (guard *GuardClient) KeyHandle(key *SecretKey) {
	if !key.IsValid() {
		fmt.Println("invalid key.")
		return
	}
	fmt.Println("Handle key: ", ConvToString(key))

	// read local secret key
	localkey := guard.store.ReadSecreKey()

	// compare secret key
	if ConvToString(key) == localkey {
		// led notification
		err := guard.pipe.SendMsg(_msg_tbled_green_blink_on_1)
		if err != nil {
			fmt.Println(err)
		}
		return
	}

	bssid := ConvToString(key)
	meshid := "n-000000"
	// store secret key
	guard.store.StoreSecretKey(bssid, meshid)

	// led notification
	err := guard.pipe.SendMsg(_msg_tbled_green_blink_on_1)
	if err != nil {
		fmt.Println(err)
	}

	// mesh network switch
	guard.wnic.MeshNetworkRestart()
}

func (guard *GuardClient) Parse(msg *Message) {

	// parse message headr
	msgtype := msg.GetMsgType()
	switch msgtype {
	case _type_msg_sync_key:
		key := Contruct(msg.GetPayload())
		guard.KeyHandle(key)
	default:
		fmt.Println("unknown message type.")
	}
}

func (guard *GuardClient) Start() {
	for {
		if guard.isExit {
			break
		}

		fmt.Println("------------------receive data-----------------------")
		payload, err := guard.chtran.Recv()
		if err != nil {
			fmt.Println(err)
			continue
		}

		msg := Message{}
		err = msg.Unmarshal(payload)
		if err != nil {
			fmt.Println("message unmarshal error", err)
		}

		fmt.Println(msg)
		guard.Parse(&msg)
	}
	guard.chsync <- 0
}

func (guard *GuardClient) Stop() {
	if !guard.isExit {
		guard.isExit = true
		<-guard.chsync
	}
}

//func Exist(filename string) bool {
//    _, err := os.Stat(filename)
//    return err == nil || os.IsExist(err)
//}

func main() {
	// parse configration file
	config := ArgParse()
	if config == nil {
		return
	}

	// protocol channel init
	var proxy IChannel = CreateProtoProxy(_broadcast_mac_addr, config.GetNicName())
	err := proxy.Open()
	if err != nil {
		fmt.Println("open network interface, err: ", err)
		return
	}
	defer proxy.Close()

	// read and handle messages from the button pipe
	var msgpipe IPipeCtrl = CreatePipeControler()
	err = msgpipe.OpenPipe(config.GetMsgPipe())
	if err != nil {
		fmt.Println("open button pipe error: ", err)
		return
	}
	defer msgpipe.ClosePipe()

	// led message pipe
	var ledpipe IPipeCtrl = CreatePipeControler()
	err = ledpipe.OpenPipe(config.GetLedPipe())
	if err != nil {
		fmt.Println("open led pipe error: ", err)
		return
	}
	defer ledpipe.ClosePipe()

	// secret key storage control
	store := StoreControler{config.GetScript()}
	// mesh network control
	wnic := WNICControler{config.GetScript()}

	// guard client for recving and handling the key sync message
	gc := GuardClient{config: config, chtran: proxy, pipe: ledpipe, store: &store, wnic: &wnic}
	gc.Open()
	go gc.Start()
	defer gc.Close()

	// guard server for sending the key sync message
	gs := GuardServer{config: config, chtran: proxy, pipe: ledpipe, store: &store, wnic: &wnic}
	gs.Open()
	defer gs.Close()

	// simple state switch
	state := _s_normal

	for {
		msg, err := msgpipe.RecvMsg()
		fmt.Println("message:  ", msg)
		if err != nil {
			fmt.Println("read button pipe error: ", err)
		} else {
			switch msg {
			case _msg_btn0_pressed_long:
				switch state {
				case _s_normal:
					go gs.Start()
					state = _s_keysync
				case _s_keysync:
					gs.Stop()
					state = _s_normal
				default:
					fmt.Println("unknown state error")

				}
			default:
				fmt.Println("message format error from button pipe.")

			}
		}
	}
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"guard/devctrl"
	"guard/message"
	"guard/protoproxy"
	"io/ioutil"
	"time"
)

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
	wnic   *devctrl.WNICControler
	store  *devctrl.StoreControler
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
	key := message.Generator()

	// not duplicate
	localkey := guard.store.ReadSecreKey()
	for message.ConvToString(key) == localkey {
		key = message.Generator()
	}

	// construct secret key message
	msg := message.Message{}
	msg.SetMsgType(_type_msg_sync_key)
	msg.SetPayLen(uint16(len(key.Elem)))
	msg.SetPayload(key.Elem[:])
	var seqseed uint16 = 0

	bassid := message.ConvToString(key)
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

		fmt.Println("send data: ", message.ConvToString(key))

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
	wnic   *devctrl.WNICControler
	store  *devctrl.StoreControler
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

func (guard *GuardClient) KeyHandle(key *message.SecretKey) {
	if !key.IsValid() {
		fmt.Println("invalid key.")
		return
	}
	fmt.Println("Handle key: ", message.ConvToString(key))

	// read local secret key
	localkey := guard.store.ReadSecreKey()

	// compare secret key
	if message.ConvToString(key) == localkey {
		// led notification
		err := guard.pipe.SendMsg(_msg_tbled_green_blink_on_1)
		if err != nil {
			fmt.Println(err)
		}
		return
	}

	bssid := message.ConvToString(key)
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

func (guard *GuardClient) Parse(msg *message.Message) {

	// parse message headr
	msgtype := msg.GetMsgType()
	switch msgtype {
	case _type_msg_sync_key:
		key := message.Contruct(msg.GetPayload())
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

		msg := message.Message{}
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
	var proxy IChannel = protoproxy.CreateProtoProxy(_broadcast_mac_addr, config.GetNicName())
	err := proxy.Open()
	if err != nil {
		fmt.Println("open network interface, err: ", err)
		return
	}
	defer proxy.Close()

	// read and handle messages from the button pipe
	var msgpipe IPipeCtrl = devctrl.CreatePipeControler()
	err = msgpipe.OpenPipe(config.GetMsgPipe())
	if err != nil {
		fmt.Println("open button pipe error: ", err)
		return
	}
	defer msgpipe.ClosePipe()

	// led message pipe
	var ledpipe IPipeCtrl = devctrl.CreatePipeControler()
	err = ledpipe.OpenPipe(config.GetLedPipe())
	if err != nil {
		fmt.Println("open led pipe error: ", err)
		return
	}
	defer ledpipe.ClosePipe()

	// secret key storage control
	store := devctrl.StoreControler{config.GetScript()}
	// mesh network control
	wnic := devctrl.WNICControler{config.GetScript()}

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

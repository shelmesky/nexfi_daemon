package main

import (
	"encoding/json"
	"flag"
	"fmt"
	chy "guard/chanproxy"
	"io/ioutil"
	"os"
	"time"
	//"guard/control"
	//"guard/message"
	//"guard/secret"
)

const (
	_s_normal = iota
	_s_keysync
)

const (
	_msg_btn0_pressed_long     = "pressed:btn0:long"
	_msg_tbled_red_blink_on    = "tbled:red:blink:on"
	_msg_tbled_red_blink_off   = "tbled:red:blink:off"
	_msg_tbled_green_blink_on  = "tbled:green:blink:on"
	_msg_tbled_green_blink_off = "tbled:green:blink:off"
)

const (
	_broadcast_mac_addr = "FF:FF:FF:FF:FF:FF"
)

/* configuration file for config some attr */
type Configuration struct {
	Script  string `json:"cmmand script"`       // the cmd script
	Keyfile string `json:"secret key file"`     // the file of storing secret key
	Nic     string `json:"nic interface"`       // the network interface for communication
	Btnpipe string `json:"button message pipe"` // the pipe of button
	Ledpipe string `json:"led message pipe"`    // the pipe of LED
}

/* setter and getter for attr */
func (c *Configuration) SetNIC(nic string)         { c.Nic = nic }
func (c *Configuration) SetScript(script string)   { c.Script = script }
func (c *Configuration) SetKeyFile(keyfile string) { c.Keyfile = keyfile }
func (c *Configuration) SetBtnPipe(btnpipe string) { c.Btnpipe = btnpipe }
func (c *Configuration) SetLEDPipe(ledpipe string) { c.Ledpipe = ledpipe }
func (c *Configuration) GetScript() string         { return c.Script }
func (c *Configuration) GetKeyFile() string        { return c.Keyfile }
func (c *Configuration) GetNIC() string            { return c.Nic }
func (c *Configuration) GetBtnPipe() string        { return c.Btnpipe }
func (c *Configuration) GetLEDPipe() string        { return c.Ledpipe }

/* strore configuration file */
func (c *Configuration) SaveConfig(filename string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	fmt.Println(data)
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

type MessagePipe struct {
	f *os.File
}

func (pipe *MessagePipe) OpenPipe(filename string) (err error) {
	pipe.f, err = os.OpenFile(filename, os.O_RDWR, 0644)
	return err
}

func (pipe *MessagePipe) RecvMsg() (string, error) {
	data := make([]byte, 1024)
	n, err := pipe.f.Read(data)
	if err != nil {
		fmt.Println("button pipe read error: ", err)
		return "", err
	}

	msg := string(data[:n-1])
	return msg, err

}

func (pipe *MessagePipe) ClosePipe() {
	pipe.f.Close()
}

type IChannel interface {
	Send(data []byte) error
	Recv() (payload []byte, err error)
}

type GuardServer struct {
	config *Configuration
	chtran IChannel // channel for transmission
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
	for {
		if guard.isExit {
			break
		}
		time.Sleep(time.Second)
		fmt.Println("Guard Server Run...............Server")
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

func (guard *GuardClient) Start() {
	for {
		if guard.isExit {
			break
		}
		payload, err := guard.chtran.Recv()
		if err != nil {
			fmt.Println(err)
			time.Sleep(time.Second)
			continue
		}
		fmt.Println("Guard Client Run Recv Data: ", string(payload))
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

	// channel init
	chproxy := chy.ChannelProxy{DesMac: _broadcast_mac_addr, NicInt: config.GetNIC()}
	err := chproxy.Open()
	if err != nil {
		fmt.Println("open network interface: ", chproxy.GetNicInt(), " err: ", err)
		return
	}
	defer chproxy.Close()

	// guard client for recving and handling the key sync message
	gc := GuardClient{config: config}
	gc.Open()
	go gc.Start()
	defer gc.Close()

	// guard server for sending the key sync message
	gs := GuardServer{config: config}
	gs.Open()
	defer gs.Close()

	// read and handle messages from the button pipe
	btnpip := MessagePipe{}
	err = btnpip.OpenPipe(config.GetBtnPipe())
	if err != nil {
		fmt.Println("open button pipe error: ", err)
		return
	}
	defer btnpip.ClosePipe()

	// simple state switch
	state := _s_normal

	for {
		msg, err := btnpip.RecvMsg()
		if err != nil {
			fmt.Println("read button pipe error: ", err)
		} else {
			switch msg {
			case _msg_btn0_pressed_long:
				switch state {
				case _s_normal:
					gc.Stop()
					go gs.Start()
					state = _s_keysync
				case _s_keysync:
					gs.Stop()
					go gc.Start()
					state = _s_normal
				default:

				}
			default:
				fmt.Println("message format error from button pipe.")

			}
		}
	}
	gc.Stop()
	gs.Stop()
}

// check configuration option
//fmt.Println(config.GetKeyFile())
//fmt.Println(config.GetNIC())
//fmt.Println(config.GetScript())
//fmt.Println(config.GetLEDPipe())
//fmt.Println(config.GetBtnPipe())
//func ConstructConfig() {
//	config := &Configuration{}
//	config.SetScript("/root/nexfid.sh")
//	config.SetKeyFile("/root/key")
//	config.SetNIC("br-lan")
//	config.SetBtnPipe("/tmp/btnfifo")
//	config.SetLEDPipe("/tmp/ledfifo")
//	config.SaveConfig("./config.json")
//}

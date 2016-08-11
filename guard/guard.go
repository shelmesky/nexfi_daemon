package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	//"guard/chanproxy"
	//"guard/control"
	//"guard/message"
	//"guard/secret"
)

/* configuration file for config some attr */
type Configuration struct {
	Script  string `json:"cmmand script"`       // the cmd script with full path
	Keyfile string `json:"secret key file"`     // the file with full path for storing secret key
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

func ConstructConfig() {
	config := &Configuration{}
	config.SetScript("/root/nexfid.sh")
	config.SetKeyFile("/root/key")
	config.SetNIC("br-lan")
	config.SetBtnPipe("/tmp/btnfifo")
	config.SetLEDPipe("/tmp/ledfifo")
	config.SaveConfig("./config.json")
}

type IGuardState interface {
	Open()
	Close()
	Run()
}

type GuardServer struct {
	config *Configuration
}

func (guard *GuardServer) Open() {}

func (guard *GuardServer) Close() {}

func (guard *GuardServer) Run() {}

type GuardClient struct {
	config *Configuration
}

func (guard *GuardClient) Open() {}

func (guard *GuardClient) Close() {}

func (guard *GuardClient) Run() {}

//func Exist(filename string) bool {
//    _, err := os.Stat(filename)
//    return err == nil || os.IsExist(err)
//}

func main() {
	/* construct configration file */
	config := ArgParse()
	if config == nil {
		return
	}

	fmt.Println(config.GetKeyFile())
	fmt.Println(config.GetNIC())
	fmt.Println(config.GetScript())
	fmt.Println(config.GetLEDPipe())
	fmt.Println(config.GetBtnPipe())
	//	ConstructConfig()
	//	fmt.Println("guard")
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	//"guard/chanproxy"
	//"guard/control"
	//"guard/message"
	//"guard/secret"
)

import "io/ioutil"

// Configuration Class
type Configuration struct {
	Script string // the cmd script with full path
	File   string // the file with full path for storing secret key
	NIC    string // the network interface for communication
}

func (c *Configuration) SetNIC(nic string) {
	c.NIC = nic
}

func (c *Configuration) SetScript(script string) {
	c.Script = script
}

func (c *Configuration) SetFile(file string) {
	c.File = file
}

func (c *Configuration) GetScript() string {
	return c.Script
}

func (c *Configuration) GetFile() string {
	return c.File
}

func (c *Configuration) GetNIC() string {
	return c.NIC
}

/* strore configuration file */
func (c *Configuration) SaveConfig(filename string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, data, 0666)
	if err != nil {
		return err
	}

	return nil
}

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

func ArgParse() *Configuration {
	var usage string = `nexfid 1.0.1,  nexfi secret key distribution deamon
			    Basic usage:
			    nexfid -f finlename
			    Options:`
	filename := flag.String("f", "", "The filename of configuration.")
	if filename == nil {
		return nil
	}

	flag.Parse()
	if flag.NFlag() != 1 {
		fmt.Println(usage)
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
	config.SetFile("/root/key.sh")
	config.SetNIC("br-lan")
	config.SaveConfig("./config.json")
}

func main() {
	/* construct configration file */
	config := ArgParse()
	if config == nil {
		return
	}

	fmt.Println(config.GetFile())
	fmt.Println(config.GetNIC())
	fmt.Println(config.GetScript())
	// ConstructConfig()
}

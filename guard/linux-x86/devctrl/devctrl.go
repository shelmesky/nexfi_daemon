package devctrl

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

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

package devctrl

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

const (
	_opcode_network_restart = "2"
	_opcode_store_key       = "1"
	_opcode_read_key        = "0"
)

const (
	_max_recv_buf_size = 1024
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
	err, out := Exec(
		"/bin/sh",
		ctl.CmdScript,
		_opcode_network_restart)

	if err != nil {
		fmt.Println(err)
	}
}

/* Store controler for storing the secret key to file */
type StoreControler struct {
	CmdScript string
}

func (ctl *StoreControler) StoreSecretKey(bssid string, meshid string) {
	opcode := "1"
	err, out := Exec(
		"/bin/sh",
		ctl.CmdScript,
		_opcode_store_key,
		bssid,
		meshid)

	if err != nil {
		fmt.Println(err)
	}
}

func (ctl *StoreControler) ReadSecreKey() string {
	err, out := Exec(
		"/bin/sh",
		ctl.CmdScript,
		_opcode_read_key)

	if err != nil {
		fmt.Println(err)
	}
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
	data := make([]byte, _max_recv_buf_size)
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

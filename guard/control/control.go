package control

import (
	"os/exec"
)

func Exec(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	/* var out bytes.Buffer
	cmd.Stdout = &out */
	return cmd.Run()
}

/* LED controler for controling led and tri-base color led */
type LEDControler struct {
	CmdScript string
}

func (ctl *LEDControler) TriBRedBlinking() error {
	return nil
}

func (ctl *LEDControler) TriBGreenBlinking() error {
	return nil
}

/* Wireless Network Interface Card controler for restarting the wireless mesh network */
type WNICControler struct {
	CmdScript string
}

func (ctl *WNICControler) RestartMesh() error {
	return nil
}

/* Store controler for storing the secret key to file */
type StoreControler struct {
	FileName string
}

func (ctl *StoreControler) StoreFile(key []byte) error {
	return nil
}

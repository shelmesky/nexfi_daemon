// +build linux

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

var (
	monitor_interface string
	server_address    string
)

type afpacket struct {
	ifce       *net.Interface
	fd         int
	sockaddrLL *syscall.SockaddrLinklayer
}

func init() {
	flag.StringVar(&monitor_interface, "i", "", "Network interface name to monitor")
	flag.StringVar(&server_address, "s", "", "http server address")
}

func CheckFlags() {
	flag.Parse()

	if monitor_interface == "" {
		fmt.Println("need network interface name")
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

func newDev(ifce *net.Interface) (*afpacket, error) {
	var err error

	d := new(afpacket)
	d.ifce = ifce

	d.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(0x0003))
	if err != nil {
		return d, err
	}

	d.sockaddrLL = new(syscall.SockaddrLinklayer)
	d.sockaddrLL.Ifindex = ifce.Index
	d.sockaddrLL.Protocol = uint16(htons(0x0003))
	syscall.Bind(d.fd, d.sockaddrLL)

	return d, err
}

func (d *afpacket) Interface() *net.Interface {
	return d.ifce
}

func (d *afpacket) Close() error {
	return syscall.Close(d.fd)
}

func (d *afpacket) Read(to []byte) error {
	_, _, err := syscall.Recvfrom(d.fd, to, 0)
	if err != nil {
		return err
	}
	return nil
}

func HandleFrame(frame []byte) {
	lens := int(frame[2])

	// beacon frame
	/*
		if frame[lens] == 0x80 {
			mac := frame[lens+10 : lens+16]
			ssid := frame[lens+38 : (lens + 38 + int(frame[lens+37]))]
			mac_str := fmt.Sprintf("%x:%x:%x:%x:%x:%x", int(mac[0]), int(mac[1]), int(mac[2]), int(mac[3]), int(mac[4]), int(mac[5]))
			ssid_str := string(ssid)
			fmt.Printf("MAC: %s, SSID: %s\n", mac_str, ssid_str)
		}
	*/

	// probe request frame
	if frame[lens] == 0x40 {
		mac := frame[lens+10 : lens+16]
		ssid := frame[lens+26 : (lens + 26 + int(frame[lens+25]))]
        ssi_signal := 256 - int(frame[30])
		mac_str := fmt.Sprintf("%x:%x:%x:%x:%x:%x", int(mac[0]), int(mac[1]), int(mac[2]), int(mac[3]), int(mac[4]), int(mac[5]))
		ssid_str := string(ssid)
        fmt.Printf("MAC: %s, SSID: %s SSI: -%d\n", mac_str, ssid_str, ssi_signal)
	}
}

func main() {
	CheckFlags()

	iface, err := net.InterfaceByName(monitor_interface)
	if err != nil {
		fmt.Println(err)
		return
	}

	dev, err := newDev(iface)
	if err != nil {
		fmt.Println(err)
		return
	}

	frame := make([]byte, 2048)
	for {
		err := dev.Read(frame)
		if err != nil {
			fmt.Println(err)
			continue
		}
		HandleFrame(frame)
	}
}

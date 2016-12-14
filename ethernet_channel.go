// +build linux

package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

var (
	nic_interface    string
	dest_mac_address string
	is_sender        bool
	is_receiver      bool
	content          string

	MAX_PAYLOAD_SIZE int = 1024
	ETHER_TYPE           = [2]byte{0x55, 0xaa}
)

func init() {
	flag.StringVar(&nic_interface, "i", "", "network interface to send ethernet frame")
	flag.StringVar(&nic_interface, "interface", "", "network interface to send ethernet frame")

	flag.StringVar(&dest_mac_address, "t", "", "mac address of destination node")
	flag.StringVar(&dest_mac_address, "to", "", "mac address of destination node")

	flag.BoolVar(&is_sender, "s", false, "this is sender")
	flag.BoolVar(&is_sender, "sender", false, "this is sender")

	flag.BoolVar(&is_receiver, "r", false, "this is receiver")
	flag.BoolVar(&is_receiver, "receiver", false, "this is receiver")

	flag.StringVar(&content, "c", "", "string content to send")
	flag.StringVar(&content, "-content", "", "string content to send")
}

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

func (d *afpacket) SetKernelFilter() (err error) {
	var sock_fprog syscall.SockFprog

	sock_filter := []syscall.SockFilter{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 1, 0x000055aa},
		{0x6, 0, 0, 0x0000ffff},
		{0x6, 0, 0, 0x00000000},
	}

	sock_fprog.Len = uint16(len(sock_filter))
	sock_fprog.Filter = &sock_filter[0]

	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(d.fd), uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER), uintptr(unsafe.Pointer(&sock_fprog)), 0x10, 0)

	if errno != 0 {
		err = errno
		return err
	}

	return nil
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

func CheckFlags() {
	flag.Parse()

	if is_sender == false && is_receiver == false {
		fmt.Println("must be sender or receiver.")
		goto EXIT
	}

	if is_sender == true && is_receiver == true {
		fmt.Println("can not be sender and receiver in same time.")
		goto EXIT
	}

	if nic_interface == "" {
		fmt.Println("Need interface name")
		goto EXIT
	}

	if is_sender == true && dest_mac_address == "" {
		fmt.Println("we are sender, but destination mac address is empty.")
		goto EXIT
	}

	if is_sender == true && content == "" {
		fmt.Println("Need content")
		goto EXIT
	}

	return

EXIT:
	os.Exit(1)
}

func main() {
	CheckFlags()

	iface, err := net.InterfaceByName(nic_interface)
	if err != nil {
		fmt.Println(err)
		return
	}

	dev, err := newDev(iface, nil, MAX_PAYLOAD_SIZE)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = dev.SetKernelFilter()
	if err != nil {
		fmt.Println(err)
		return
	}

	if is_sender == true {
		err = dev.SendFrame(dest_mac_address, []byte(content))
		if err != nil {
			fmt.Println(err)
		}
	}

	if is_receiver == true {
		for {
			payload, err := dev.RecvFrame()
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(payload))
		}
	}
}

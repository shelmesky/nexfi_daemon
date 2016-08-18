package protoproxy

import "net"

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

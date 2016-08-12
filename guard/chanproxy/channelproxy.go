package chanproxy

import "net"

type ChannelProxy struct {
	DesMac string //destination mac address
	NicInt string //network interface car
	DevNic *afpacket
}

func (c *ChannelProxy) SetDesMac(mac string) { c.DesMac = mac }
func (c *ChannelProxy) GetDesMac() string    { return c.DesMac }
func (c *ChannelProxy) SetNicInt(nic string) { c.NicInt = nic }
func (c *ChannelProxy) GetNicInt() string    { return c.NicInt }

func (c *ChannelProxy) Send(data []byte) error {
	return c.DevNic.SendFrame(c.DesMac, data)
}

func (c *ChannelProxy) Close() error {
	return c.DevNic.Close()
}

func (c *ChannelProxy) Open() error {
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

func (c *ChannelProxy) Recv() (payload []byte, err error) {
	return c.DevNic.RecvFrame()
}

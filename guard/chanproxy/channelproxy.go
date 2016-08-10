package chanproxy

import ()

type ChannelProxy struct {
	DesMac string //destination mac address
	NicInt string //network interface car
}

func (c *ChannelProxy) SetDesMac(mac string) {
	c.DesMac = mac
}

func (c *ChannelProxy) GetDesMac() string {
	return c.DesMac
}

func (c *ChannelProxy) SetNicInt(nic string) {
	c.NicInt = nic
}

func (c *ChannelProxy) GetNicInit() string {
	return c.NicInt
}

func (c *ChannelProxy) Send(data []byte) error {
	return nil
}

func (c *ChannelProxy) Close() error {
	return nil
}

func (c *ChannelProxy) Open() error {
	return nil
}

func (c *ChannelProxy) RecvFrame() (payload []byte, err error) {
	return nil, nil
}

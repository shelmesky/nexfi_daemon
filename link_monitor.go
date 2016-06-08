package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	MAC_ADDRESS_PATH = "/sys/devices/platform/ar933x_wmac/net/wlan0/phy80211/macaddress"
	DHCP_CLIENT      = "/sbin/udhcpc"
	BRIDGE_PHY_PORT  = "eth0"
)

func main() {
	l, _ := ListenNetlink()

	for {
		msgs, err := l.ReadMsgs()
		if err != nil {
			fmt.Println("Could not read netlink: %s", err)
		}

		for _, m := range msgs {

			if m.Header.Type == syscall.RTM_NEWLINK || m.Header.Type == syscall.RTM_DELLINK {

				ifim := (*syscall.IfInfomsg)(unsafe.Pointer(&m.Data[0]))

				if (ifim.Flags & 0x10000) == 0 {
					fmt.Printf("DOWN ")
				} else {
					fmt.Printf("UP ")
				}

				route_attrs, err := syscall.ParseNetlinkRouteAttr(&m)
				if err != nil {
					fmt.Println("failed:", err)
					os.Exit(1)
				}

				for _, attr := range route_attrs {
					if attr.Attr.Type == syscall.IFLA_IFNAME {
						fmt.Printf("%s\n", string(attr.Value))
						break
					}
				}
			}

			if IsNewAddr(&m) {
				fmt.Println("New Addr")
			}

			if IsDelAddr(&m) {
				fmt.Println("Del Addr")
			}
		}
	}
}

type NetlinkListener struct {
	fd int
	sa *syscall.SockaddrNetlink
}

func ListenNetlink() (*NetlinkListener, error) {
	groups := syscall.RTNLGRP_LINK |
		syscall.RTNLGRP_IPV4_IFADDR |
		syscall.RTNLGRP_IPV6_IFADDR

	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM,
		syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("socket: %s", err)
	}

	saddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(0),
		Groups: uint32(groups),
	}

	err = syscall.Bind(s, saddr)
	if err != nil {
		return nil, fmt.Errorf("bind: %s", err)
	}

	return &NetlinkListener{fd: s, sa: saddr}, nil
}

func (l *NetlinkListener) ReadMsgs() ([]syscall.NetlinkMessage, error) {
	defer func() {
		recover()
	}()

	pkt := make([]byte, 2048)

	n, err := syscall.Read(l.fd, pkt)
	if err != nil {
		return nil, fmt.Errorf("read: %s", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(pkt[:n])
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	return msgs, nil
}

func IsNewAddr(msg *syscall.NetlinkMessage) bool {
	if msg.Header.Type == syscall.RTM_NEWADDR {
		return true
	}

	return false
}

func IsDelAddr(msg *syscall.NetlinkMessage) bool {
	if msg.Header.Type == syscall.RTM_DELADDR {
		return true
	}

	return false
}

func IsRelevant(msg *syscall.IfAddrmsg) bool {
	if msg.Scope == syscall.RT_SCOPE_UNIVERSE ||
		msg.Scope == syscall.RT_SCOPE_SITE {
		return true
	}

	return false
}

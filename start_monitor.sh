#!/bin/sh

PHY=phy0
IFACE=mon0

iw phy $PHY interface add $IFACE type monitor flags none control otherbss
ifconfig $IFACE up promisc


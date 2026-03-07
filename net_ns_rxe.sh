#!/bin/sh

# Notes:
#
# 1. Before running this script, please disable the firewall, as it may
# block UDP port 4791.

# 2. This test script depends on the veth and tun drivers. Before running
#  the script, please verify that both drivers are available by executing:
#
# modinfo tun
# modinfo veth
#
# Make sure these commands return valid module information.

set -x
#1. Check if rping can work or not
ip netns add test1
ip netns ls
ip link add veth-a type veth peer name veth-b
ip l
ip link set veth-a netns test1
ip l
ip netns exec test1 ip l set veth-a up
ip netns exec test1 ip addr add 1.1.1.1/24 dev veth-a
ip netns exec test1 ip l
ip netns exec test1 ip -4 a
ip netns exec test1 rdma link add rxe0 type rxe netdev veth-a

#check if socket exist or not
ip netns exec test1 ss -lun | grep :4791

ip netns exec test1 rdma link
ip link set veth-b up
ip addr add 1.1.1.2/24 dev veth-b
ping -c 3 1.1.1.1 || exit 1
ip netns exec test1 rping -s -a 1.1.1.1&
rdma link add rxe1 type rxe netdev veth-b
rdma link

#check if socket exist or not
ss -lun | grep :4791

rping -c -a 1.1.1.1 -d -v -C 3
ip netns ls
rdma link del rxe1

#check if socket exist or not
ss -lun | grep :4791

ip netns exec test1 ss -lun | grep :4791
ip netns exec test1 rdma link del rxe0
ip netns exec test1 ss -lun | grep :4791
ip netns del test1
ip netns ls

#2. Check if socket exist or not
ip tuntap add mode tun tun0
ip -4 a
ip addr add 1.1.1.1/24 dev tun0
ip link set tun0 up
ip -4 a
rdma link add rxe0 type rxe netdev tun0
rdma link
ss -lun | grep :4791

ip tuntap add mode tun tun1
ip -4 a
ip addr add 2.2.2.2/24 dev tun1
ip link set tun1 up
rdma link add rxe1 type rxe netdev tun1
rdma link
ss -lun | grep :4791

rdma link del rxe1
rdma link
ss -lun | grep :4791

rdma link del rxe0
rdma link
ss -lun | grep :4791

ip addr del 2.2.2.2/24 dev tun1
ip tuntap del mode tun tun1

ip addr del 1.1.1.1/24 dev tun0
ip tuntap del mode tun tun0
modprobe -v -r tun

# 3. ipv6 test.
# While RXE is conventionally deployed over IPv4, it maintains
# native support for IPv6. However, IPv6 implementations typically
# receive less validation and performance tuning in standard use cases.

# 1) create ipv6 net namespace
set -x
ip netns add net6
ip link add veth0 type veth peer name veth1
ip link set veth1 netns net6
ip netns exec net6 ip addr add 2001:db8::1/64 dev veth1
ip netns exec net6 ip link set veth1 up

# 2) Add rdma link
ip netns exec net6 rdma link add rxe6 type rxe netdev veth1

# 3) check IPv6 UDP 4791 listening port
ip netns exec net6 ss -ul6n | grep :4791

# 4) Delete rxe link
ip netns exec net6 rdma link del rxe6
ip netns exec net6 ss -ul6n | grep :4791  # result should be null

# 5) delete net6
ip netns del net6

#4. Trigger NETDEV_UNREGISTER
ip tuntap add mode tun tun0
ip -4 a
ip addr add 1.1.1.1/24 dev tun0
ip link set tun0 up
ip -4 a
rdma link add rxe0 type rxe netdev tun0
rdma link
ss -lun | grep :4791

ip l
ip addr del 1.1.1.1/24 dev tun0
ip tuntap del mode tun tun0

rdma link
ss -lun | grep :4791

modprobe -v -r tun
modprobe -v -r rdma_rxe
set +x

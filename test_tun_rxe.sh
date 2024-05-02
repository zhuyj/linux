set -x
ip tuntap add mode tun tun0
ip -4 a
ip addr add 1.1.1.1/24 dev tun0
ip link set tun0 up
ip -4 a
rdma link add rxe0 type rxe netdev tun0
rdma link
rping -s -a 1.1.1.1&
dmesg -c
rping -c -a 1.1.1.1 -d -v -C 3
rdma link del rxe0
rdma link
ip addr del 1.1.1.1/24 dev tun0
ip tuntap del mode tun tun0
modprobe -v -r tun
set +x

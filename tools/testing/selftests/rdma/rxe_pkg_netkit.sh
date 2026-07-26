#!/bin/sh

CUR_WD=`pwd`

echo > /sys/kernel/debug/tracing/trace
ip netns delete ns0
ip netns add ns0

ip link delete nk1

# clang -O2 -g -target bpf -c $CUR_WD/rxe_pkg_kernel_dump.c -o $CUR_WD/dump.o
# bpftool gen skeleton $CUR_WD/dump.o > $CUR_WD/user_skeleton.h
# gcc -o $CUR_WD/u_dump $CUR_WD/rxe_pkg_user_dump.c -lbpf -lelf -lz

#ip link add nk1 type netkit
ip link add nk0 type netkit mode l2 peer name nk1
#sleep 3
ip link set nk0 up
ip link set nk1 up

ip link

ip link set nk0 netns ns0
ip netns exec ns0 ip addr add 10.0.0.1/24 dev nk0
ip netns exec ns0 ip link set nk0 up
ip netns exec ns0 ip link
ip netns exec ns0 ip -4 a
ip addr add 10.0.0.2/24 dev nk1
#ip link set dev nk1 tcx_ingress obj dump.o sec handle_netkit_ingress
#ip tcx attach dev nk1 ingress obj dump.o
#sleep 3
#bpftool net attach tcx_ingress id 129 dev nk1

# Load ebpf
#rm -Rf /sys/fs/bpf/netkit
#mkdir -p /sys/fs/bpf/netkit
#bpftool prog load dump.o /sys/fs/bpf/netkit/netkit_dump 
#bpftool net attach tcx_ingress name handle_netkit_ingress dev nk1
$CUR_WD/rxe_netkit_dump &

sleep 3
#bpftool prog load dump.bpf.o /sys/fs/bpf/netkit/netkit_dump
#bpftool net attach tcx_ingress name handle_ingress dev nk1
#./packet_dump &

# bpftool prog show
# bpftool net list

ip -4 a
ip l
#sleep 3
# ping -c 3 10.0.0.1 -I nk1

ip netns exec ns0 rdma link add rxe0 type rxe netdev nk0
#ip netns exec ns0 rdma link

rdma link add rxe1 type rxe netdev nk1
#rdma link

#ip -s link

ip netns exec ns0 rping -s -a 10.0.0.1 -C 3&
#ip netns exec ns0 ibv_rc_pingpong -g 1 &
sleep 3
rping -c -a 10.0.0.1 -C 3 
#ibv_rc_pingpong -g 1 10.0.0.1

#ip -s link

#ip netns exec ns0 ip -s link

ip netns exec ns0 rdma link del rxe0
rdma link del rxe1

ip link del nk1

ip netns delete ns0

cat /sys/kernel/debug/tracing/trace

killall -9 rxe_netkit_dump

rm -f $CUR_WD/rxe_netkit_dump $CUR_WD/rxe_pkg_kernel_dump.o $CUR_WD/rxe_pkg_kernel.skel.h

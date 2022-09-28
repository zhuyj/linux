ip netns delete net0
ip netns delete net1

ip l
sleep 5
ip l

ip netns add net0
ip link set dev eno2 netns net0
ip netns exec net0 ip link
ip netns exec net0 ip addr add 192.168.2.1/24 dev eno2
ip netns exec net0 ip link set eno2 up
ip netns exec net0 ip -4 a
ip netns exec net0 rdma link add rxe0 type rxe netdev eno2
ip netns exec net0 rdma link
ip netns exec net0 ss -lu

ip netns add net1
ip link set dev enxf8e43b3be410 netns net1
ip netns exec net1 ip link
ip netns exec net1 ip addr add 192.168.2.2/24 dev enxf8e43b3be410
ip netns exec net1 ip link set enxf8e43b3be410 up
ip netns exec net1 ip -4 a
ip netns exec net1 rdma link add rxe1 type rxe netdev enxf8e43b3be410
ip netns exec net1 rdma link
ip netns exec net1 ss -lu

sleep 3
ip netns exec net0 rping -s -a 192.168.2.1 -C 3&
sleep 3
ip netns exec net1 rping -c -a 192.168.2.1 -d -v -C 3

sleep 3
ip netns exec net0 rdma link del rxe0
sleep 3
ip netns exec net1 rdma link del rxe1

sleep 3
ip netns exec net0 ss -lu
ip netns exec net1 ss -lu

sleep 3
ip netns exec net0 rdma link
ip netns exec net1 rdma link

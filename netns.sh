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
rdma link
ip netns exec test1 rdma link
ip netns exec test1 rping -s -a 1.1.1.1&
ip link set veth-b up
ip addr add 1.1.1.2/24 dev veth-b
ping -c 3 1.1.1.1
rdma link add rxe1 type rxe netdev veth-b
rping -c -a 1.1.1.1 -d -v -C 3
ip netns ls
ip netns del test1
ip netns ls

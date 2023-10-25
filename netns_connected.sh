set -x
ip netns add test1
ip netns ls
sleep 2
ip link add veth-a type veth peer name veth-b
ip l
sleep 2
ip link set veth-a netns test1
ip l
sleep 2
ip netns exec test1 ip l set veth-a up
ip netns exec test1 ip addr add 1.1.1.1/24 dev veth-a
ip netns exec test1 ip l
sleep 2
ip netns exec test1 ip -4 a
sleep 2
ip netns exec test1 rdma link add rxe0 type rxe netdev veth-a
ip netns exec test1 rdma link
ip netns exec test1 rping -s -a 1.1.1.1 -d -v&

ip netns add test2
ip netns ls
sleep 2
ip link set veth-b netns test2
ip l
sleep 2
ip netns exec test2 ip l set veth-b up
ip netns exec test2 ip addr add 1.1.1.2/24 dev veth-b
ip netns exec test2 ip l
ip netns exec test2 ip -4 a
sleep 2
ip netns exec test2 rdma link add rxe1 type rxe netdev veth-b
ip netns exec test2 rdma link
ip netns exec test2 ping -c 3 1.1.1.1
ip netns exec test2 rping -c -a 1.1.1.1 -d -v -C 3

ip netns ls
ip netns del test1
ip netns del test2
ip netns ls
set +x

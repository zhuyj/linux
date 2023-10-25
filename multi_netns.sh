set -x
ip netns add one
ip netns add two
ip netns add three
ip link add veth-one-in   type veth peer name veth-one-out
ip link add veth-two-in   type veth peer name veth-two-out
ip link add veth-three-in type veth peer name veth-three-out

ip link set veth-one-in   netns one
ip link set veth-two-in   netns two
ip link set veth-three-in netns three
ip netns exec one   ip addr add 10.0.0.10/24 dev veth-one-in
ip netns exec two   ip addr add 10.0.0.20/24 dev veth-two-in
ip netns exec three ip addr add 10.0.0.30/24 dev veth-three-in

ip link add name virtual-bridge type bridge

ip link set veth-one-out   master virtual-bridge
ip link set veth-two-out   master virtual-bridge
ip link set veth-three-out master virtual-bridge

ip link set virtual-bridge up
ip link set veth-one-out   up
ip link set veth-two-out   up
ip link set veth-three-out up
ip netns exec one ip link   set dev veth-one-in   up
ip netns exec two ip link   set dev veth-two-in   up
ip netns exec three ip link set dev veth-three-in up
ip netns exec one ip link   set dev lo up
ip netns exec two ip link   set dev lo up
ip netns exec three ip link set dev lo up

ip netns exec one ping 10.0.0.10 -c1
ip netns exec one ping 10.0.0.20 -c1
ip netns exec one ping 10.0.0.30 -c1

ip netns exec one rdma link add rxe1 type rxe netdev veth-one-in
ip netns exec two rdma link add rxe2 type rxe netdev veth-two-in
ip netns exec three rdma link add rxe3 type rxe netdev veth-three-in

rdma link
ip netns exec one rping -s -a 10.0.0.10&
ip netns exec two rping -c -a 10.0.0.10 -d -v -C 3
ip netns exec one rping -s -a 10.0.0.10&
ip netns exec three rping -c -a 10.0.0.10 -d -v -C 3

ip netns del one
ip netns del two
ip netns del three
set +x

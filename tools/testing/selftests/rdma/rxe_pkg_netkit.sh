#!/bin/sh
# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
# Copyright (c) 2026 Zhu Yanjun <yanjun.zhu@linux.dev>
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: This test must be run as root"
    exit 4
fi

for cmd in ip rdma rping; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "SKIP: Required tool '$cmd' not found"
        exit 4
    fi
done

if ! modprobe -n netkit >/dev/null 2>&1 || ! modprobe -n rdma_rxe >/dev/null 2>&1; then
    echo "SKIP: Required kernel modules (netkit or rdma_rxe) are not available"
    exit 4
fi

exec > /dev/null

set -e

CUR_WD="$(dirname "$0")"
[ "$CUR_WD" = "." ] && CUR_WD="$(pwd)"

cleanup() {
    set +e
    [ -n "$DUMP_PID" ] && kill -9 "$DUMP_PID" 2>/dev/null
    unset DUMP_PID

    rdma link del rxe1 2>/dev/null
    ip link del nk0 2>/dev/null
    ip netns delete ns0 2>/dev/null

    rm -f "$CUR_WD/rxe_netkit_dump" "$CUR_WD/rxe_pkg_kernel_dump.o" "$CUR_WD/rxe_pkg_kernel.skel.h"
}

trap cleanup EXIT INT TERM

# Clear tracing buffer
echo > /sys/kernel/debug/tracing/trace

# Create network namespace and netkit peer links
ip netns add ns0
ip link add nk0 type netkit mode l2 peer name nk1
ip link set nk0 up
ip link set nk1 up

# Configure namespace interface
ip link set nk1 netns ns0
ip netns exec ns0 ip addr add 10.0.0.1/24 dev nk1
ip netns exec ns0 ip link set nk1 up

# Configure host interface
ip addr add 10.0.0.2/24 dev nk0

# Start dump utility in background
"$CUR_WD/rxe_netkit_dump" &
DUMP_PID=$!

# Add RXE links over netkit devices
ip netns exec ns0 rdma link add rxe0 type rxe netdev nk1
rdma link add rxe1 type rxe netdev nk0

# Start rping server in namespace
ip netns exec ns0 rping -s -a 10.0.0.1 -C 3 &

# Add wait time
sleep 1

# Run rping client on host
rping -c -a 10.0.0.1 -C 3

# Tear down RDMA links and netkit devices
ip netns exec ns0 rdma link del rxe0
rdma link del rxe1
ip link del nk0
ip netns delete ns0

# Display kernel trace output
cat /sys/kernel/debug/tracing/trace

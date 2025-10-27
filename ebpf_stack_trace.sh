#!/bin/sh
WORKDIR=/home/coder/Development/linux
cd $WORKDIR && make -C tools/testing/selftests/bpf
cd $WORKDIR/tools/testing/selftests/bpf && sudo ./test_progs -t get_stack_raw_tp || exit 1
sudo cat /sys/kernel/debug/tracing/trace

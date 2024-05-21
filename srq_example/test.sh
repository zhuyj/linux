#!/bin/sh
CUR_DIR=`pwd`
killall -9 rdma_server
echo "RQ tests"
${CUR_DIR}/rdma_server -s 1.1.1.1 &
sleep 3
${CUR_DIR}/rdma_client -s 1.1.1.1
killall -9 rdma_server
echo "SRQ tests"
${CUR_DIR}/rdma_server -s 1.1.1.1 -e &
sleep 3
${CUR_DIR}/rdma_client -s 1.1.1.1 -e

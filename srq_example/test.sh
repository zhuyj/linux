#!/bin/sh
CUR_DIR=`pwd`
killall -9 srq_server
${CUR_DIR}/srq_server -s -a 1.1.1.1 &
sleep 3
${CUR_DIR}/srq_client -a 1.1.1.1

make M=drivers/infiniband/sw/rxe modules || exit 1
if [ ! -d /lib/modules/`uname -r`/updates/drivers/infiniband/sw/rxe/ ]; then
	mkdir -p /lib/modules/`uname -r`/updates/drivers/infiniband/sw/rxe/
fi
cp -f drivers/infiniband/sw/rxe//rdma_rxe.ko /lib/modules/`uname -r`/updates/drivers/infiniband/sw/rxe/rdma_rxe.ko
md5sum drivers/infiniband/sw/rxe//rdma_rxe.ko
md5sum /lib/modules/`uname -r`/updates/drivers/infiniband/sw/rxe/rdma_rxe.ko
depmod -a
update-initramfs -u

modprobe -v -r rdma_rxe && modprobe -v rdma_rxe

ip addr add 192.168.2.2/24 dev eno2
ip link set eno2 up

ip link set enxf8e43b3be410 up
ip addr add 192.168.3.2/24 dev enxf8e43b3be410

#rdma link delete rxe0
#rdma link delete rxe1
#modprobe -v -r rdma_rxe
#modprobe -v rdma_rxe

#ip addr add 192.168.1.1/24 dev enp0s8
#ip link set enp0s8 up


#!/bin/sh
make M=drivers/infiniband/sw/rxe/ modules || exit 0
if [ ! -d /lib/modules/`uname -r`/updates/drivers/infiniband/sw/rxe/ ]; then
        mkdir -p /lib/modules/`uname -r`/updates/drivers/infiniband/sw/rxe/
fi
cp drivers/infiniband/sw/rxe//rdma_rxe.ko /lib/modules/`uname -r`/updates/drivers/infiniband/sw/rxe/
depmod -a
dracut -f
modinfo rdma_rxe

all:
	gcc srq_server.c -o srq_server -libverbs -lrdmacm
	gcc srq_client.c -o srq_client -libverbs -lrdmacm
	gcc rdma_client.c -o rdma_client -libverbs -lrdmacm
	gcc rdma_server.c -o rdma_server -libverbs -lrdmacm
clean:
	rm -f srq_server srq_client rdma_client rdma_server

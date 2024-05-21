/*
 * Copyright (c) 2005-2009 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <stdbool.h>

static char *server_name = "0.0.0.0";
static char *server_port = "7471";
static bool enable_srq = false;

static struct rdma_cm_id *listen_id, *rq_id;
static struct ibv_mr *recv_mr, *send_mr;
static int send_flags;
static uint8_t send_buf[16];
static uint8_t recv_buf[16];

#define VERB_ERR(verb, ret) \
        fprintf(stderr, "%s returned %d errno %d\n", verb, ret, errno)

/* Default parameters values */
#define DEFAULT_MSG_COUNT 100
#define DEFAULT_MSG_LENGTH 100000
#define DEFAULT_QP_COUNT 128
#define DEFAULT_MAX_WR 64

/* Resources used in the example */
struct context {
	/* User parameters */
	char *server_name;
	char *server_port;
	int msg_count;
	int msg_length;
	int qp_count;
	int max_wr;

	/* Resources */
	struct rdma_cm_id *srq_id;
	struct rdma_cm_id **conn_id;
	struct ibv_mr *send_mr;
	struct ibv_mr *recv_mr;
	struct ibv_srq *srq;
	struct ibv_cq *srq_cq;
	struct ibv_comp_channel *srq_cq_channel;
	char *send_buf;
	char *recv_buf;
};

/*
 * Function: srq_init_resources
 * Input:
 *      ctx     The context object
 *      rai     The RDMA address info for the connection
 * Output:
 *      none
 * Returns:
 *      0 on success, non-zero on failure
 * Description:
 *      This function initializes resources that are common to both the client
 *      and server functionality.
 *      It creates our SRQ, registers memory regions, posts receive buffers
 *      and creates a single completion queue that will be used for the receive
 *      queue on each queue pair.
 */
int srq_init_resources(struct context *ctx, struct rdma_addrinfo *rai)
{
	int ret, i;
	struct rdma_cm_id *id;

	/* Create an ID used for creating/accessing our SRQ */
	ret = rdma_create_id(NULL, &ctx->srq_id, NULL, RDMA_PS_TCP);
	if (ret) {
		VERB_ERR("rdma_create_id", ret);
		return ret;
	}

	/* We need to bind the ID to a particular RDMA device
	 * This is done by resolving the address or binding to the address */
	ret = rdma_bind_addr(ctx->srq_id, rai->ai_src_addr);
	if (ret) {
		VERB_ERR("rdma_bind_addr", ret);
		return ret;
	}

	/* Create the memory regions being used in this example */
	ctx->recv_mr =
	    rdma_reg_msgs(ctx->srq_id, ctx->recv_buf, ctx->msg_length);
	if (!ctx->recv_mr) {
		VERB_ERR("rdma_reg_msgs", -1);
		return -1;
	}

	ctx->send_mr =
	    rdma_reg_msgs(ctx->srq_id, ctx->send_buf, ctx->msg_length);
	if (!ctx->send_mr) {
		VERB_ERR("rdma_reg_msgs", -1);
		return -1;
	}

	/* Create our shared receive queue */
	struct ibv_srq_init_attr srq_attr;
	memset(&srq_attr, 0, sizeof(srq_attr));
	srq_attr.attr.max_wr = ctx->max_wr;
	srq_attr.attr.max_sge = 1;

	ret = rdma_create_srq(ctx->srq_id, NULL, &srq_attr);
	if (ret) {
		VERB_ERR("rdma_create_srq", ret);
		return -1;
	}

	/* Save the SRQ in our context so we can assign it to other QPs later */
	ctx->srq = ctx->srq_id->srq;

	/* Post our receive buffers on the SRQ */
	for (i = 0; i < ctx->max_wr; i++) {
		ret =
		    rdma_post_recv(ctx->srq_id, NULL, ctx->recv_buf,
				   ctx->msg_length, ctx->recv_mr);
		if (ret) {
			VERB_ERR("rdma_post_recv", ret);
			return ret;
		}
	}

	/* Create a completion channel to use with the SRQ CQ */
	ctx->srq_cq_channel = ibv_create_comp_channel(ctx->srq_id->verbs);
	if (!ctx->srq_cq_channel) {
		VERB_ERR("ibv_create_comp_channel", -1);
		return -1;
	}

	/* Create a CQ to use for all connections (QPs) that use the SRQ */
	ctx->srq_cq = ibv_create_cq(ctx->srq_id->verbs, ctx->max_wr, NULL,
				    ctx->srq_cq_channel, 0);
	if (!ctx->srq_cq) {
		VERB_ERR("ibv_create_cq", -1);
		return -1;
	}

	/* Make sure that we get notified on the first completion */
	ret = ibv_req_notify_cq(ctx->srq_cq, 0);
	if (ret) {
		VERB_ERR("ibv_req_notify_cq", ret);
		return ret;
	}

	return 0;
}

/*
 * Function:    srq_destroy_resources
 * Input:
 *      ctx     The context object
 * Output:
 *      none
 * Returns:
 *      0 on success, non-zero on failure
 * Description:
 *      This function cleans up resources used by the application
 */
void srq_destroy_resources(struct context *ctx)
{
	int i;

	if (ctx->conn_id) {
		for (i = 0; i < ctx->qp_count; i++) {
			if (ctx->conn_id[i]) {
				if (ctx->conn_id[i]->qp &&
				    ctx->conn_id[i]->qp->state == IBV_QPS_RTS) {
					rdma_disconnect(ctx->conn_id[i]);
				}
				rdma_destroy_qp(ctx->conn_id[i]);
				rdma_destroy_id(ctx->conn_id[i]);
			}
		}

		free(ctx->conn_id);
	}

	if (ctx->recv_mr)
		rdma_dereg_mr(ctx->recv_mr);

	if (ctx->send_mr)
		rdma_dereg_mr(ctx->send_mr);

	if (ctx->recv_buf)
		free(ctx->recv_buf);

	if (ctx->send_buf)
		free(ctx->send_buf);

	if (ctx->srq_cq)
		ibv_destroy_cq(ctx->srq_cq);

	if (ctx->srq_cq_channel)
		ibv_destroy_comp_channel(ctx->srq_cq_channel);

	if (ctx->srq_id) {
		rdma_destroy_srq(ctx->srq_id);
		rdma_destroy_id(ctx->srq_id);
	}
}

/*
 * Function:    srq_await_completion
 * Input:
 *      ctx     The context object
 * Output:
 *      none
 * Returns:
 *      0 on success, non-zero on failure
 * Description:
 *      Waits for a completion on the SRQ CQ
 */
int srq_await_completion(struct context *ctx)
{
	int ret;
	struct ibv_cq *ev_cq;
	void *ev_ctx;

	/* Wait for a CQ event to arrive on the channel */
	ret = ibv_get_cq_event(ctx->srq_cq_channel, &ev_cq, &ev_ctx);
	if (ret) {
		VERB_ERR("ibv_get_cq_event", ret);
		return ret;
	}

	ibv_ack_cq_events(ev_cq, 1);

	/* Reload the event notification */
	ret = ibv_req_notify_cq(ctx->srq_cq, 0);
	if (ret) {
		VERB_ERR("ibv_req_notify_cq", ret);
		return ret;
	}

	return 0;
}

/*
 * Function:    srq_run_server
 * Input:
 *      ctx     The context object
 *      rai     The RDMA address info for the connection
 * Output:
 *      none
 * Returns:
 *      0 on success, non-zero on failure
 * Description:
 *      Executes the server side of the example
 */
int srq_run_server(struct context *ctx, struct rdma_addrinfo *rai)
{
	int ret, i;
	uint64_t send_count = 0;
	uint64_t recv_count = 0;
	struct ibv_wc wc;
	struct ibv_qp_init_attr qp_attr;

	ret = srq_init_resources(ctx, rai);
	if (ret) {
		printf("init_resources returned %d\n", ret);
		return ret;
	}

	ret = rdma_listen(ctx->srq_id, 4);
	if (ret) {
		VERB_ERR("rdma_listen", ret);
		return ret;
	}

	printf("waiting for connection from client...\n");
	for (i = 0; i < ctx->qp_count; i++) {
		ret = rdma_get_request(ctx->srq_id, &ctx->conn_id[i]);
		if (ret) {
			VERB_ERR("rdma_get_request", ret);
			return ret;
		}

		/* Create the queue pair */
		memset(&qp_attr, 0, sizeof(qp_attr));

		qp_attr.qp_context = ctx;
		qp_attr.qp_type = IBV_QPT_RC;
		qp_attr.cap.max_send_wr = ctx->max_wr;
		qp_attr.cap.max_recv_wr = ctx->max_wr;
		qp_attr.cap.max_send_sge = 1;
		qp_attr.cap.max_recv_sge = 1;
		qp_attr.cap.max_inline_data = 0;
		qp_attr.recv_cq = ctx->srq_cq;
		qp_attr.srq = ctx->srq;
		qp_attr.sq_sig_all = 0;

		ret = rdma_create_qp(ctx->conn_id[i], NULL, &qp_attr);
		if (ret) {
			VERB_ERR("rdma_create_qp", ret);
			return ret;
		}

		/* Set the new connection to use our SRQ */
		ctx->conn_id[i]->srq = ctx->srq;

		ret = rdma_accept(ctx->conn_id[i], NULL);
		if (ret) {
			VERB_ERR("rdma_accept", ret);
			return ret;
		}
	}

	while (recv_count < ctx->msg_count) {
		i = 0;
		while (i < ctx->max_wr && recv_count < ctx->msg_count) {
			int ne;

			ret = srq_await_completion(ctx);
			if (ret) {
				printf("await_completion %d\n", ret);
				return ret;
			}

			do {
				ne = ibv_poll_cq(ctx->srq_cq, 1, &wc);
				if (ne < 0) {
					VERB_ERR("ibv_poll_cq", ne);
					return ne;
				} else if (ne == 0)
					break;

				if (wc.status != IBV_WC_SUCCESS) {
					printf("work completion status %s\n",
					       ibv_wc_status_str(wc.status));
					return -1;
				}

				recv_count++;
				printf("recv count: %lu, qp_num: %d\n",
				       recv_count, wc.qp_num);

				ret =
				    rdma_post_recv(ctx->srq_id,
						   (void *)wc.wr_id,
						   ctx->recv_buf,
						   ctx->msg_length,
						   ctx->recv_mr);
				if (ret) {
					VERB_ERR("rdma_post_recv", ret);
					return ret;
				}
				//              printf("ctx->msg_length:%d\n", ctx->msg_length);

				i++;
			}
			while (ne);
		}

		ret = rdma_post_send(ctx->conn_id[0], NULL, ctx->send_buf,
				     ctx->msg_length, ctx->send_mr,
				     IBV_SEND_SIGNALED);
		if (ret) {
			VERB_ERR("rdma_post_send", ret);
			return ret;
		}

		ret = rdma_get_send_comp(ctx->conn_id[0], &wc);
		if (ret <= 0) {
			VERB_ERR("rdma_get_send_comp", ret);
			return -1;
		}

		send_count++;
		printf("send count: %lu\n", send_count);
	}

	return 0;
}

static int run(void)
{
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr init_attr;
	struct ibv_qp_attr qp_attr;
	struct ibv_wc wc;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = RAI_PASSIVE;
	hints.ai_port_space = RDMA_PS_TCP;
	ret = rdma_getaddrinfo(server_name, server_port, &hints, &res);
	if (ret) {
		printf("rdma_getaddrinfo: %s\n", gai_strerror(ret));
		return ret;
	}

	memset(&init_attr, 0, sizeof init_attr);
	init_attr.cap.max_send_wr = init_attr.cap.max_recv_wr = 1;
	init_attr.cap.max_send_sge = init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_inline_data = 16;
	init_attr.sq_sig_all = 1;
	ret = rdma_create_ep(&listen_id, res, NULL, &init_attr);
	if (ret) {
		perror("rdma_create_ep");
		goto out_free_addrinfo;
	}

	ret = rdma_listen(listen_id, 0);
	if (ret) {
		perror("rdma_listen");
		goto out_destroy_listen_ep;
	}

	ret = rdma_get_request(listen_id, &rq_id);
	if (ret) {
		perror("rdma_get_request");
		goto out_destroy_listen_ep;
	}

	memset(&qp_attr, 0, sizeof qp_attr);
	memset(&init_attr, 0, sizeof init_attr);
	ret = ibv_query_qp(rq_id->qp, &qp_attr, IBV_QP_CAP, &init_attr);
	if (ret) {
		perror("ibv_query_qp");
		goto out_destroy_accept_ep;
	}
	if (init_attr.cap.max_inline_data >= 16)
		send_flags = IBV_SEND_INLINE;
	else
		printf("rdma_server: device doesn't support IBV_SEND_INLINE, "
		       "using sge sends\n");

	recv_mr = rdma_reg_msgs(rq_id, recv_buf, 16);
	if (!recv_mr) {
		ret = -1;
		perror("rdma_reg_msgs for recv_msg");
		goto out_destroy_accept_ep;
	}
	if ((send_flags & IBV_SEND_INLINE) == 0) {
		send_mr = rdma_reg_msgs(rq_id, send_buf, 16);
		if (!send_mr) {
			ret = -1;
			perror("rdma_reg_msgs for send_msg");
			goto out_dereg_recv;
		}
	}

	ret = rdma_post_recv(rq_id, NULL, recv_buf, 16, recv_mr);
	if (ret) {
		perror("rdma_post_recv");
		goto out_dereg_send;
	}

	ret = rdma_accept(rq_id, NULL);
	if (ret) {
		perror("rdma_accept");
		goto out_dereg_send;
	}

	while ((ret = rdma_get_recv_comp(rq_id, &wc)) == 0) ;
	if (ret < 0) {
		perror("rdma_get_recv_comp");
		goto out_disconnect;
	}

	ret = rdma_post_send(rq_id, NULL, send_buf, 16, send_mr, send_flags);
	if (ret) {
		perror("rdma_post_send");
		goto out_disconnect;
	}

	while ((ret = rdma_get_send_comp(rq_id, &wc)) == 0) ;
	if (ret < 0)
		perror("rdma_get_send_comp");
	else
		ret = 0;

 out_disconnect:
	rdma_disconnect(rq_id);
 out_dereg_send:
	if ((send_flags & IBV_SEND_INLINE) == 0)
		rdma_dereg_mr(send_mr);
 out_dereg_recv:
	rdma_dereg_mr(recv_mr);
 out_destroy_accept_ep:
	rdma_destroy_ep(rq_id);
 out_destroy_listen_ep:
	rdma_destroy_ep(listen_id);
 out_free_addrinfo:
	rdma_freeaddrinfo(res);
	return ret;
}

int main(int argc, char **argv)
{
	int op, ret;

	while ((op = getopt(argc, argv, "s:p:e")) != -1) {
		switch (op) {
		case 's':
			server_name = optarg;
			break;
		case 'p':
			server_port = optarg;
			break;
		case 'e':
			enable_srq = true;
			break;
		default:
			printf("usage: %s\n", argv[0]);
			printf("\t[-s server_address]\n");
			printf("\t[-p port_number]\n");
			printf("\t[-e enable srq]\n");
			exit(1);
		}
	}

	if (!enable_srq) {
		printf("rdma_server: rq start\n");
		ret = run();
		printf("rdma_server: rq end %d\n", ret);
	} else {
		struct context ctx;
		struct rdma_addrinfo *rai, hints;

		ret = 0;
		memset(&ctx, 0, sizeof(ctx));
		memset(&hints, 0, sizeof(hints));

		ctx.server_port = server_port;
		ctx.msg_count = DEFAULT_MSG_COUNT;
		ctx.msg_length = DEFAULT_MSG_LENGTH;
		ctx.qp_count = DEFAULT_QP_COUNT;
		ctx.max_wr = DEFAULT_MAX_WR;
		ctx.server_name = server_name;

		if (ctx.server_name == NULL) {
			printf("server address required (use -s)!\n");
			exit(1);
		}

		hints.ai_port_space = RDMA_PS_TCP;
		hints.ai_flags = RAI_PASSIVE;	/* this makes it a server */

		ret =
		    rdma_getaddrinfo(ctx.server_name, ctx.server_port, &hints,
				     &rai);
		if (ret) {
			VERB_ERR("rdma_getaddrinfo", ret);
			exit(1);
		}

		/* allocate memory for our QPs and send/recv buffers */
		ctx.conn_id = (struct rdma_cm_id **)calloc(ctx.qp_count,
							   sizeof(struct
								  rdma_cm_id
								  *));
		memset(ctx.conn_id, 0, sizeof(ctx.conn_id));

		ctx.send_buf = (char *)malloc(ctx.msg_length);
		memset(ctx.send_buf, 0, ctx.msg_length);
		ctx.recv_buf = (char *)malloc(ctx.msg_length);
		memset(ctx.recv_buf, 0, ctx.msg_length);

		printf("rdma_server: srq start\n");
		ret = srq_run_server(&ctx, rai);
		printf("rdma_server: srq end %d\n", ret);
		srq_destroy_resources(&ctx);
		free(rai);

		return ret;

	}
	return ret;
}

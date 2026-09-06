// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Zhu Yanjun <yanjun.zhu@linux.dev>
 */

/*
 * Selftests for the Live Update Orchestrator.
 * This test suite verifies the functionality and behavior of the
 * /dev/liveupdate character device and its session management capabilities.
 *
 * Tests include:
 * - Resource preservation for rxe: successfully preserving/unpreserving rxe resources,
 *   verifying resources remain accessible.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <libliveupdate.h>
#include <linux/liveupdate.h>

#include "../kselftest.h"
#include "../kselftest_harness.h"

#define LIVEUPDATE_DEV "/dev/liveupdate"

FIXTURE(liveupdate_device) {
	int fd1;
	int fd2;
};

FIXTURE_SETUP(liveupdate_device)
{
	self->fd1 = -1;
	self->fd2 = -1;
	system("modprobe -v rdma_rxe");
}

FIXTURE_TEARDOWN(liveupdate_device)
{
	system("modprobe -v -r rdma_rxe");
	if (self->fd1 >= 0)
		close(self->fd1);
	if (self->fd2 >= 0)
		close(self->fd2);
}

/*
 * Test Case: Preserve/Unpreserve rxe resource
 *
 */
TEST_F(liveupdate_device, preserve_rxe_fd)
{
	int session_fd;
	int ret;

	system("rdma link add rxe0 type rxe netdev lo");
	system("rdma link");
	self->fd1 = open(LIVEUPDATE_DEV, O_RDWR);
	if (self->fd1 < 0 && errno == ENOENT)
		SKIP(return, "%s does not exist", LIVEUPDATE_DEV);
	ASSERT_GE(self->fd1, 0);

	session_fd = luo_create_session(self->fd1, "rxe-fd-test");
	ASSERT_GE(session_fd, 0);

	ret = luo_session_preserve_fd(session_fd, 0, 0xEFFE);
	EXPECT_EQ(ret, 0);

	system("rdma link del rxe0");
	ASSERT_EQ(close(session_fd), 0);
}

TEST_HARNESS_MAIN

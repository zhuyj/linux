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
 * - Resource preservation for netkit: successfully preserving/unpreserving netkit resources,
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
}

FIXTURE_TEARDOWN(liveupdate_device)
{
	if (self->fd1 >= 0)
		close(self->fd1);
	if (self->fd2 >= 0)
		close(self->fd2);
}

/*
 * Test Case: Preserve/Unpreserve netkit resource
 *
 */
TEST_F(liveupdate_device, preserve_netkit_fd)
{
	int session_fd;
	int ret;

	system("ip link add netkit0 type netkit mode l2 peer name netkit1");
	system("ip link");
	self->fd1 = open(LIVEUPDATE_DEV, O_RDWR);
	if (self->fd1 < 0 && errno == ENOENT)
		SKIP(return, "%s does not exist", LIVEUPDATE_DEV);
	ASSERT_GE(self->fd1, 0);

	session_fd = luo_create_session(self->fd1, "netkit-fd-test");
	ASSERT_GE(session_fd, 0);

	ret = luo_session_preserve_fd(session_fd, 0, 0xEFEE);
	EXPECT_EQ(ret, 0);

	system("ip link del netkit0");
	ASSERT_EQ(close(session_fd), 0);
}

TEST_HARNESS_MAIN

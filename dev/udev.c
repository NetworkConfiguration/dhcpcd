/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2013 Roy Marples <roy@marples.name>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE

#include <libudev.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "../common.h"
#include "../dhcpcd.h"
#include "../eloop.h"
#include "udev.h"

static struct udev_monitor *monitor;

static void
libudev_handledata(__unused void *arg)
{
	struct udev_device *device;
	const char *ifname, *action;

	device = udev_monitor_receive_device(monitor);
	if (device == NULL) {
		syslog(LOG_DEBUG, "libudev: received NULL device");
		return;
	}

	/* udev filter documentation says "usually" so double check */
	action = udev_device_get_subsystem(device);
	if (strcmp(action, "net"))
		return;

	ifname = udev_device_get_sysname(device);
	action = udev_device_get_action(device);
	if (strcmp(action, "add") == 0)
		handle_interface(1, ifname);
	else if (strcmp(action, "remove") == 0)
		handle_interface(-1, ifname);
}

int
libudev_listening(void)
{

	return monitor == NULL ? 0 : 1;
}

void
libudev_stop(void)
{
	struct udev *udev;

	if (monitor) {
		udev = udev_monitor_get_udev(monitor);
		udev_unref(udev);
		udev_monitor_unref(monitor);
		monitor = NULL;
	}
}

int
libudev_start(void)
{
	struct udev *udev;
	int fd;

	syslog(LOG_DEBUG, "libudev: starting");
	udev = udev_new();
	if (udev == NULL) {
		syslog(LOG_ERR, "udev_new: %m");
		return -1;
	}
	monitor = udev_monitor_new_from_netlink(udev, "udev");
	if (monitor == NULL) {
		syslog(LOG_ERR, "udev_monitor_new_from_netlink: %m");
		goto bad;
	}
#ifdef LIBUDEV_FILTER
	if (udev_monitor_filter_add_match_subsystem_devtype(monitor,
	    "net", NULL) != 0)
	{
		syslog(LOG_ERR,
		    "udev_monitor_filter_add_match_subsystem_devtype: %m");
		goto bad;
	}
#endif
	if (udev_monitor_enable_receiving(monitor) != 0) {
		syslog(LOG_ERR, "udev_monitor_enable_receiving: %m");
		goto bad;
	}
	fd = udev_monitor_get_fd(monitor);
	if (fd == -1) {
		syslog(LOG_ERR, "udev_monitor_get_fd: %m");
		goto bad;
	}
	if (eloop_event_add(fd, libudev_handledata, NULL) == -1) {
		syslog(LOG_ERR, "%s: eloop_event_add: %m", __func__);
		goto bad;
	}

	atexit(libudev_stop);

	return fd;
bad:

	libudev_stop();
	return -1;
}

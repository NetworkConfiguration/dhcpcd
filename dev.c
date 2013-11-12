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

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "common.h"
#include "dev.h"
#include "eloop.h"
#include "dhcpcd.h"

static struct dev *dev;
static void *handle;
static int fd = -1;

static struct dev_dhcpcd dev_dhcpcd = {
	.handle_interface = &handle_interface
};

int
dev_initialized(const char *ifname)
{

	if (dev == NULL)
		return 1;
	return dev->initialized(ifname);
}

int
dev_listening(void)
{

	if (dev == NULL)
		return 0;
	return dev->listening();
}

void
dev_stop(void)
{

	if (dev) {
		syslog(LOG_DEBUG, "dev: unloaded %s", dev->name);
		dev->stop();
		free(dev);
		dev = NULL;
	}
	if (handle) {
		dlclose(handle);
		handle = NULL;
	}
}

static int
dev_start2(const char *name)
{
	char file[PATH_MAX];
	void *h;
	void (*fptr)(struct dev *, const struct dev_dhcpcd *);
	int r;

	snprintf(file, sizeof(file), DEVDIR "/%s", name);
	h = dlopen(file, RTLD_LAZY);
	if (h == NULL) {
		syslog(LOG_ERR, "dlopen: %s", dlerror());
		return -1;
	}
	fptr = (void (*)(struct dev *, const struct dev_dhcpcd *))
	    dlsym(h, "dev_init");
	if (fptr == NULL) {
		syslog(LOG_ERR, "dlsym: %s", dlerror());
		dlclose(h);
		return -1;
	}
	dev = calloc(1, sizeof(*dev));
	fptr(dev, &dev_dhcpcd);
	if (dev->start  == NULL || (r = dev->start()) == -1) {
		free(dev);
		dev = NULL;
		dlclose(h);
		return -1;
	}
	syslog(LOG_INFO, "dev: loaded %s", dev->name);
	handle = h;
	return r;
}

static int
dev_start1(const char *plugin)
{
	DIR *dp;
	struct dirent *d;
	int r;

	if (dev) {
		syslog(LOG_ERR, "dev: already started %s", dev->name);
		return -1;
	}

	if (plugin)
		return dev_start2(plugin);

	dp = opendir(DEVDIR);
	if (dp == NULL) {
		syslog(LOG_DEBUG, "dev: %s: %m", DEVDIR);
		return 0;
	}

	r = 0;
	while ((d = readdir(dp))) {
		if (d->d_name[0] == '.')
			continue;

		r = dev_start2(d->d_name);
		if (r != -1)
			break;
	}
	closedir(dp);
	return r;
}

static void
dev_handle_data(__unused void *arg)
{

	if (dev->handle_device() == -1) {
		/* XXX: an error occured. should we restart dev? */
	}
}

int
dev_start(const char *plugin)
{

	if (fd != -1) {
		syslog(LOG_ERR, "%s: already started on fd %d", __func__, fd);
		return fd;
	}

	fd = dev_start1(plugin);
	if (fd != -1) {
		if (eloop_event_add(fd, dev_handle_data, NULL) == -1) {
			syslog(LOG_ERR, "%s: eloop_event_add: %m", __func__);
			dev_stop();
			return -1;
		}
	}

	return fd;
}

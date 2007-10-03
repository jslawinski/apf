/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2007 jeremian <jeremian [at] poczta.fm>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <config.h>

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifndef _JS_CLIENT_REVERSE_UDP_H
#define _JS_CLIENT_REVERSE_UDP_H

#include <sys/ioctl.h>

#include "activefor.h"
#include "stats.h"
#include "logging.h"
#include "ssl_fd_struct.h"
#include "client_realm_struct.h"

int initialize_client_reverse_udp(ClientRealm* cr);
void client_reverse_udp(ClientRealm* cr, unsigned char* buff, int buflength);

#endif

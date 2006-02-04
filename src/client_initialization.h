/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2006 jeremian <jeremian [at] poczta.fm>
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

#include "activefor.h"
#include "stats.h"
#include "logging.h"
#include "http_proxy_client.h"
#include "http_proxy_options_struct.h"
#include "ssl_fd_struct.h"
#include "client_realm_struct.h"

#include <openssl/ssl.h>

#ifndef _JS_CLIENT_INITIALIZATION_H
#define _JS_CLIENT_INITIALIZATION_H

int initialize_client_stage1(ClientRealm* cr, SSL_CTX* ctx, unsigned char* buff, char wanttoexit,
    char ignorePublicKeys);
int initialize_client_stage2(ClientRealm* cr, unsigned char* buff, char wanttoexit);
int initialize_client_stage3(ClientRealm* cr, int* buflength, fd_set* allset, fd_set* wset, int* maxfdp1,
    char wanttoexit);

#endif

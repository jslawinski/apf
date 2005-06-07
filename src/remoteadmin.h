/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003,2004,2005 jeremian <jeremian [at] poczta.fm>
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

#include "file.h"
#include "stats.h"
#include "logging.h"
#include "activefor.h"
#include "realmnames.h"
#include "clientnames.h"
#include "usernames.h"
#include "make_ssl_handshake.h"
  
#include <openssl/err.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#ifndef _JS_REMOTEADMIN_H
#define _JS_REMOTEADMIN_H

#define AF_RA_UNDEFINED 0
#define AF_RA_CMD       1
#define AF_RA_REPEAT    2
#define AF_RA_STATUS_OK 3
#define AF_RA_NOT_KNOWN 4
#define AF_RA_FAILED    5
#define AF_RA_KICKED    6

int serve_admin(ConfigurationT*, int, int, unsigned char*);
int client_admin(char, clifd, unsigned char*, int, char*);

#endif


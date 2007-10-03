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

#ifndef _JS_SERVER_REMOTEADMIN_H
#define _JS_SERVER_REMOTEADMIN_H

#include <ctype.h>
#include <string.h>

#include "remoteadmin_codes.h"
#include "activefor.h"
#include "logging.h"
#include "stats.h"
#include "clientnames.h"
#include "realmnames.h"
#include "usernames.h"

int serve_admin(ServerConfiguration*, int, int, unsigned char*);

#endif

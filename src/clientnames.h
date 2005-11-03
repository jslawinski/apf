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

#include "activefor.h"
#include "server_realm_struct.h"

#ifndef _JS_CLIENTNAMES_H
#define _JS_CLIENTNAMES_H

char* get_clientname(ServerRealm*, int);
int get_clientid(ServerRealm*, char*);
int get_clientnumber(ServerRealm*, int);

char* get_raclientname(ServerRealm*, int);
int get_raclientid(ServerRealm*, char*);
int get_raclientnumber(ServerRealm*, int);

#endif


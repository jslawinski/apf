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

#ifndef _JS_REMOVE_CLIENT_TASK_H
#define _JS_REMOVE_CLIENT_TASK_H

#define RCT_REASON_TIMEOUT 0
#define RCT_REASON_MAXIDLE 1

#include "server_configuration_struct.h"

typedef struct {
  ServerConfiguration* config;
  int realm;
  int client;
  char ra;
  char reason;
  fd_set* set;
  fd_set* wset;
} RCTdata;

/* 'constructor' */
RCTdata* RCTdata_new(ServerConfiguration* config, int realm, int client, char ra, char reason,
    fd_set* set, fd_set* wset);
/* 'destructor' */
void RCTdata_free(void** data);
/* other */
void RCTfunction(void*);

#endif

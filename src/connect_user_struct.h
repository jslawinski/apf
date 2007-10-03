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


#ifndef _JS_CONNECT_USER_STRUCT_H
#define _JS_CONNECT_USER_STRUCT_H

#include <sys/types.h>

#include "buf_list_struct.h"
#include "user_stats_struct.h"

typedef struct {
  char state;
  int connFd;
  int whatClient;
  int userId;
  time_t connectTime;
  char nameBuf[128];
  char portBuf[7];
  BufList* bufList;
  UserStats* stats;
} ConnectUser;

/* 'constructor' */
ConnectUser* ConnectUser_new();
/* 'destructor' */
void ConnectUser_free(ConnectUser** cu);
/* setters */
void ConnectUser_set_state(ConnectUser* cu, char state);
void ConnectUser_set_connFd(ConnectUser* cu, int connFd);
void ConnectUser_set_whatClient(ConnectUser* cu, int whatClient);
void ConnectUser_set_userId(ConnectUser* cu, int userId);
void ConnectUser_set_connectTime(ConnectUser* cu, time_t connectTime);
void ConnectUser_set_nameBuf(ConnectUser* cu, char* nameBuf);
void ConnectUser_set_portBuf(ConnectUser* cu, char* portBuf);
void ConnectUser_set_bufList(ConnectUser* cu, BufList* bufList);
void ConnectUser_set_stats(ConnectUser* cu, UserStats* stats);
/* getters */
char ConnectUser_get_state(ConnectUser* cu);
int ConnectUser_get_connFd(ConnectUser* cu);
int ConnectUser_get_whatClient(ConnectUser* cu);
int ConnectUser_get_userId(ConnectUser* cu);
time_t ConnectUser_get_connectTime(ConnectUser* cu);
char* ConnectUser_get_nameBuf(ConnectUser* cu);
char* ConnectUser_get_portBuf(ConnectUser* cu);
BufList* ConnectUser_get_bufList(ConnectUser* cu);
UserStats* ConnectUser_get_stats(ConnectUser* cu);

#endif

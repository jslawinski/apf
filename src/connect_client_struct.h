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


#ifndef _JS_CONNECT_CLIENT_STRUCT_H
#define _JS_CONNECT_CLIENT_STRUCT_H

#include <time.h>

#include "ssl_fd_struct.h"
#include "audit_list_struct.h"
#include "header_buffer_struct.h"
#include "task_struct.h"

#define CONNECTCLIENT_STATE_UNKNOWN -1
#define CONNECTCLIENT_STATE_FREE 0
#define CONNECTCLIENT_STATE_CONNECTING 1
#define CONNECTCLIENT_STATE_AUTHORIZING 2
#define CONNECTCLIENT_STATE_ACCEPTED 3

#define CONNECTCLIENT_TUNNELTYPE_UNKNOWN -1
#define CONNECTCLIENT_TUNNELTYPE_DIRECT 0
#define CONNECTCLIENT_TUNNELTYPE_HTTPPROXY 1
#define CONNECTCLIENT_TUNNELTYPE_HTTPSPROXY 2

#define CONNECTCLIENT_MULTI_ENABLED 1
#define CONNECTCLIENT_MULTI_DISABLED 0

typedef struct {
  char state;
  SslFd* sslFd;
  struct timeval timer;
  int* users;
  int connected;
  int limit;
  int listenFd;
  int usrCliPair;
  int clientId;
  time_t connectTime;
  time_t lastActivity;
  char* sClientId;
  char nameBuf[128];
  char portBuf[7];
  char tunnelType;
  char multi;
  AuditList* auditList;
  HeaderBuffer* header;
  Task* task;
} ConnectClient;

/* 'constructor' */
ConnectClient* ConnectClient_new();
/* 'destructor' */
void ConnectClient_free(ConnectClient** cc);
/* setters */
void ConnectClient_set_state(ConnectClient* cc, char state);
void ConnectClient_set_sslFd(ConnectClient* cc, SslFd* sf);
void ConnectClient_set_timer(ConnectClient* cc, struct timeval timer);
void ConnectClient_set_users(ConnectClient* cc, int* users);
void ConnectClient_set_connected(ConnectClient* cc, int connected);
void ConnectClient_set_limit(ConnectClient* cc, int limit);
void ConnectClient_set_listenFd(ConnectClient* cc, int listenFd);
void ConnectClient_set_usrCliPair(ConnectClient* cc, int usrCliPair);
void ConnectClient_set_clientId(ConnectClient* cc, int clientId);
void ConnectClient_set_connectTime(ConnectClient* cc, time_t connectTime);
void ConnectClient_set_lastActivity(ConnectClient* cc, time_t lastActivity);
void ConnectClient_set_sClientId(ConnectClient* cc, char* sClientId);
void ConnectClient_set_nameBuf(ConnectClient* cc, char* nameBuf);
void ConnectClient_set_portBuf(ConnectClient* cc, char* portBuf);
void ConnectClient_set_tunnelType(ConnectClient* cc, char tunnelType);
void ConnectClient_set_multi(ConnectClient* cc, char multi);
void ConnectClient_set_auditList(ConnectClient* cc, AuditList* al);
void ConnectClient_set_header(ConnectClient* cc, HeaderBuffer* hb);
void ConnectClient_set_task(ConnectClient* cc, Task* task);
/* getters */
char ConnectClient_get_state(ConnectClient* cc);
SslFd* ConnectClient_get_sslFd(ConnectClient* cc);
struct timeval ConnectClient_get_timer(ConnectClient* cc);
int* ConnectClient_get_users(ConnectClient* cc);
int ConnectClient_get_connected(ConnectClient* cc);
int ConnectClient_get_limit(ConnectClient* cc);
int ConnectClient_get_listenFd(ConnectClient* cc);
int ConnectClient_get_usrCliPair(ConnectClient* cc);
int ConnectClient_get_clientId(ConnectClient* cc);
time_t ConnectClient_get_connectTime(ConnectClient* cc);
time_t ConnectClient_get_lastActivity(ConnectClient* cc);
char* ConnectClient_get_sClientId(ConnectClient* cc);
char* ConnectClient_get_nameBuf(ConnectClient* cc);
char* ConnectClient_get_portBuf(ConnectClient* cc);
char ConnectClient_get_tunnelType(ConnectClient* cc);
char ConnectClient_get_multi(ConnectClient* cc);
AuditList* ConnectClient_get_auditList(ConnectClient* cc);
HeaderBuffer* ConnectClient_get_header(ConnectClient* cc);
Task* ConnectClient_get_task(ConnectClient* cc);
/* other */
int ConnectClient_create_users(ConnectClient* cc);
struct timeval* ConnectClient_get_timerp(ConnectClient* cc);
void ConnectClient_increase_connected(ConnectClient* cc);
void ConnectClient_decrease_connected(ConnectClient* cc);
int* ConnectClient_get_listenFdp(ConnectClient* cc);

#endif

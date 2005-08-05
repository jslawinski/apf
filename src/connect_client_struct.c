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

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include "string_functions.h"
#include "timeval_functions.h"
#include "connect_client_struct.h"

/*
 * Function name: ConnectClient_new
 * Description: Create and initialize new ConnectClient structure.
 * Returns: Pointer to newly created ConnectClient structure.
 */

ConnectClient*
ConnectClient_new()
{
  ConnectClient* tmp = calloc(1, sizeof(ConnectClient));
  if (tmp == NULL) {
    return NULL;
  }
  tmp->sslFd = SslFd_new();
  if (tmp->sslFd == NULL) {
    ConnectClient_free(&tmp);
    return NULL;
  }
  tmp->auditList = AuditList_new();
  if (tmp->auditList == NULL) {
    ConnectClient_free(&tmp);
    return NULL;
  }
  tmp->header = HeaderBuffer_new();
  if (tmp->header == NULL) {
    ConnectClient_free(&tmp);
    return NULL;
  }
  return tmp;
}

/*
 * Function name: ConnectClient_free
 * Description: Free the memory allocated for ConnectClient structure.
 * Arguments: cc - pointer to pointer to ConnectClient structure
 */

void
ConnectClient_free(ConnectClient** cc)
{
  SslFd* sftmp;
  AuditList* altmp;
  if (cc == NULL) {
    return;
  }
  if ((*cc) == NULL) {
    return;
  }
  sftmp = ConnectClient_get_sslFd((*cc));
  altmp = ConnectClient_get_auditList((*cc));
  SslFd_free(&sftmp);
  AuditList_free(&altmp);
  if ((*cc)->users) {
    free((*cc)->users);
    (*cc)->users = NULL;
  }
  if ((*cc)->sClientId) {
    free((*cc)->sClientId);
    (*cc)->sClientId = NULL;
  }
  free((*cc));
  (*cc) = NULL;
}

/*
 * Function name: ConnectClient_set_state
 * Description: Set state of the connected client.
 * Arguments: cc - pointer to ConnectClient structure
 *            state - state of the connected client
 */

void
ConnectClient_set_state(ConnectClient* cc, char state)
{
  if (cc == NULL) {
    return;
  }
  cc->state = state;
}

/*
 * Function name: ConnectClient_set_sslFd
 * Description: Set SslFd structure.
 * Arguments: cc - pointer to ConnectClient structure
 *            sf - SslFd structure
 */

void
ConnectClient_set_sslFd(ConnectClient* cc, SslFd* sf)
{
  SslFd* sftmp;
  if (cc == NULL) {
    return;
  }
  sftmp = ConnectClient_get_sslFd(cc);
  SslFd_free(&sftmp);
  cc->sslFd = sf;
}

/*
 * Function name: ConnectClient_set_timer
 * Description: Set timer of the client used for internal time counting.
 * Arguments: cc - pointer to ConnectClient structure
 *            timer - timer of the client used for internal time counting
 */

void
ConnectClient_set_timer(ConnectClient* cc, struct timeval timer)
{
  if (cc == NULL) {
    return;
  }
  cc->timer = timer;
}

/*
 * Function name: ConnectClient_set_users
 * Description: Set users descriptor table.
 * Arguments: cc - pointer to ConnectClient structure
 *            users - users descriptor table
 */

void
ConnectClient_set_users(ConnectClient* cc, int* users)
{
  if (cc == NULL) {
    return;
  }
  if (cc->users) {
    free(cc->users);
  }
  cc->users = users;
}

/*
 * Functions name: ConnectClient_set_connected
 * Description: Set number of connected users.
 * Arguments: cc - pointer to ConnectClient structure
 *            connected - number of connected users
 */

void
ConnectClient_set_connected(ConnectClient* cc, int connected)
{
  if (cc == NULL) {
    return;
  }
  cc->connected = connected;
}

/*
 * Function name: ConnectClient_set_limit
 * Description: Set limit of connected users.
 * Arguments: cc - pointer to ConnectClient structure
 *            limit - limit of connected users
 */

void
ConnectClient_set_limit(ConnectClient* cc, int limit)
{
  if (cc == NULL) {
    return;
  }
  cc->limit = limit;
}

/*
 * Function name: ConnectClient_set_listenFd
 * Description: Set listen socket descriptor.
 * Arguments: cc - pointer to ConnectClient structure
 *            listenFd - listen socket descriptor
 */

void
ConnectClient_set_listenFd(ConnectClient* cc, int listenFd)
{
  if (cc == NULL) {
    return;
  }
  cc->listenFd = listenFd;
}

/*
 * Function name: ConnectClient_set_usrCliPair
 * Description: Set user-client pair number.
 * Arguments: cc - pointer to ConnectClient structure
 *            usrCliPair - user-client pair number
 */

void
ConnectClient_set_usrCliPair(ConnectClient* cc, int usrCliPair)
{
  if (cc == NULL) {
    return;
  }
  cc->usrCliPair = usrCliPair;
}

/*
 * Function name: ConnectClient_set_clientId
 * Description: Set client identification number.
 * Arguments: cc - pointer to ConnectClient structure
 *            clientId - client identification number
 */

void
ConnectClient_set_clientId(ConnectClient* cc, int clientId)
{
  if (cc == NULL) {
    return;
  }
  cc->clientId = clientId;
}

/*
 * Function name: ConnectClient_set_connectTime
 * Description: Set start time of the connection.
 * Arguments: cc - pointer to ConnectClient structure
 *            connectTime - start time of the connection
 */

void
ConnectClient_set_connectTime(ConnectClient* cc, time_t connectTime)
{
  if (cc == NULL) {
    return;
  }
  cc->connectTime = connectTime;
}

/*
 * Function name: ConnectClient_set_sClientId
 * Description: Set client identification string.
 * Arguments: cc - pointer to ConnectClient structure
 *            sClientId - client identification string
 */

void
ConnectClient_set_sClientId(ConnectClient* cc, char* sClientId)
{
  if (cc == NULL) {
    return;
  }
  string_cp(&(cc->sClientId), sClientId);
}

/*
 * Function name: ConnectClient_set_nameBuf
 * Description: Set name of the client.
 * Arguments: cc - pointer to ConnectClient structure
 *            nameBuf - name of the client
 */

void
ConnectClient_set_nameBuf(ConnectClient* cc, char* nameBuf)
{
  if (cc == NULL) {
    return;
  }
  memset(cc->nameBuf, 0, 128);
  strncpy(cc->nameBuf, nameBuf, 127);
}

/*
 * Function name: ConnectClient_set_portBuf
 * Description: Set port from which client is connected.
 * Arguments: cc - pointer to ConnectClient structure
 *            portBuf - port from which client is connected
 */

void
ConnectClient_set_portBuf(ConnectClient* cc, char* portBuf)
{
  if (cc == NULL) {
    return;
  }
  memset(cc->portBuf, 0, 7);
  strncpy(cc->portBuf, portBuf, 6);
}

/*
 * Function name: ConnectClient_set_tunnelType
 * Description: Set tupe of the client tunnel.
 * Arguments: cc - pointer to ConnectClient structure
 *            tunnelType - tupe of the client tunnel
 */

void
ConnectClient_set_tunnelType(ConnectClient* cc, char tunnelType)
{
  if (cc == NULL) {
    return;
  }
  cc->tunnelType = tunnelType;
}

/*
 * Function name: ConnectClient_set_auditList
 * Description: Set audit list for the audit feature.
 * Arguments: cc - pointer to ConnectClient structure
 *            al - audit list for the audit feature
 */

void
ConnectClient_set_auditList(ConnectClient* cc, AuditList* al)
{
  AuditList* altmp;
  if (cc == NULL) {
    return;
  }
  altmp = ConnectClient_get_auditList(cc);
  AuditList_free(&altmp);
  cc->auditList = al;
}

/*
 * Function name: ConnectClient_set_header
 * Description: Set header buffer for incomplete headers.
 * Arguments: cc - pointer to ConnectClient structure
 *            hb - header buffer for incomplete headers
 */

void
ConnectClient_set_header(ConnectClient* cc, HeaderBuffer* hb)
{
  HeaderBuffer* hbtmp;
  if (cc == NULL) {
    return;
  }
  hbtmp = ConnectClient_get_header(cc);
  HeaderBuffer_free(&hbtmp);
  cc->header = hb;
}

/*
 * Function name: ConnectClient_get_state
 * Description: Get state of the connected client.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: State of the connected client.
 */

char
ConnectClient_get_state(ConnectClient* cc)
{
  if (cc == NULL) {
    return CONNECTCLIENT_STATE_UNKNOWN;
  }
  return cc->state;
}

/*
 * Function name: ConnectClient_get_sslFd
 * Description: Get SslFd structure.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: SslFd structure.
 */

SslFd*
ConnectClient_get_sslFd(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return cc->sslFd;
}

/*
 * Function name: ConnectClient_get_timer
 * Description: Get timer of the client used for internal time counting. 
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Timer of the client used for internal time counting.
 */

struct timeval
ConnectClient_get_timer(ConnectClient* cc)
{
  if (cc == NULL) {
    return timeval_create(0, 0);
  }
  return cc->timer;
}

/*
 * Function name: ConnectClient_get_users
 * Description: Get users descriptor table.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Users descriptor table.
 */

int*
ConnectClient_get_users(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return cc->users;
}

/*
 * Function name: ConnectClient_get_connected
 * Description: Get number of connected users.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Number of connected users.
 */

int
ConnectClient_get_connected(ConnectClient* cc)
{
  if (cc == NULL) {
    return -1;
  }
  return cc->connected;
}

/*
 * Function name: ConnectClient_get_limit
 * Description: Get limit of connected users.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Limit of connected users.
 */

int
ConnectClient_get_limit(ConnectClient* cc)
{
  if (cc == NULL) {
    return -1;
  }
  return cc->limit;
}

/*
 * Function name: ConnectClient_get_listenFd
 * Description: Get listen socket descriptor.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Listen socket descriptor.
 */

int
ConnectClient_get_listenFd(ConnectClient* cc)
{
  if (cc == NULL) {
    return -1;
  }
  return cc->listenFd;
}

/*
 * Function name: ConnectClient_get_usrCliPair
 * Description: Get user-client pair number.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: User-client pair number.
 */

int
ConnectClient_get_usrCliPair(ConnectClient* cc)
{
  if (cc == NULL) {
    return -1;
  }
  return cc->usrCliPair;
}

/*
 * Function name: ConnectClient_get_clientId
 * Description: Get client identification number.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Client identification number.
 */

int
ConnectClient_get_clientId(ConnectClient* cc)
{
  if (cc == NULL) {
    return -1;
  }
  return cc->clientId;
}

/*
 * Function name: ConnectClient_get_connectTime
 * Description: Get start time of the connection.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Start time of the connection.
 */

time_t
ConnectClient_get_connectTime(ConnectClient* cc)
{
  if (cc == NULL) {
    return 0;
  }
  return cc->connectTime;
}

/*
 * Function name: ConnectClient_get_sClientId
 * Description: Get client identification string.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Client identification string.
 */

char*
ConnectClient_get_sClientId(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return cc->sClientId;
}

/*
 * Function name: ConnectClient_get_nameBuf
 * Description: Get name of the client.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Name of the client.
 */

char*
ConnectClient_get_nameBuf(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return cc->nameBuf;
}

/*
 * Function name: ConnectClient_get_portBuf
 * Description: Get port from which client is connected.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Port from which client is connected.
 */

char*
ConnectClient_get_portBuf(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return cc->portBuf;
}

/*
 * Function name: ConnectClient_get_tunnelType
 * Description: Get tupe of the client tunnel.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Tupe of the client tunnel.
 */

char
ConnectClient_get_tunnelType(ConnectClient* cc)
{
  if (cc == NULL) {
    return CONNECTCLIENT_TUNNELTYPE_UNKNOWN;
  }
  return cc->tunnelType;
}

/*
 * Function name: ConnectClient_get_auditList
 * Description: Get audit list for the audit feature.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Audit list for the audit feature.
 */

AuditList*
ConnectClient_get_auditList(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return cc->auditList;
}

/*
 * Function name: ConnectClient_get_header
 * Description: Get header buffer for incomplete headers.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Header buffer for incomplete headers.
 */

HeaderBuffer*
ConnectClient_get_header(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return cc->header;
}

/*
 * Function name: ConnectClient_create_users
 * Description: Create user descriptor table. Memory for the table is allocated according
 *              to the previously set 'limit' value. All the descriptors are set to -1.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: >0 - there were some problems with memory allocation
 *          0 - everything was ok
 */

int
ConnectClient_create_users(ConnectClient* cc)
{
  int i, limit;
  if (cc == NULL) {
    return 1;
  }
  limit = ConnectClient_get_limit(cc);
  if (limit == -1) {
    return 2;
  }
  cc->users = malloc(limit * sizeof(int));
  if (cc->users == NULL) {
    return 3;
  }
  for (i = 0; i < limit; ++i) {
    cc->users[i] = -1;
  }
  return 0;
}

/*
 * Function name: ConnectClient_get_timerp
 * Description: Get pointer to timer of the client used for internal time counting. 
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Pointer to timer of the client used for internal time counting.
 */

struct timeval*
ConnectClient_get_timerp(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return (&(cc->timer));
}

/*
 * Function name: ConnectClient_increase_connected
 * Description: Increase number of connected users.
 * Arguments: cc - pointer to ConnectClient structure
 */

void
ConnectClient_increase_connected(ConnectClient* cc)
{
  if (cc == NULL) {
    return;
  }
  ConnectClient_set_connected(cc, ConnectClient_get_connected(cc) + 1);
}

/*
 * Function name: ConnectClient_decrease_connected
 * Description: Decrease number of connected users.
 * Arguments: cc - pointer to ConnectClient structure
 */

void
ConnectClient_decrease_connected(ConnectClient* cc)
{
  if (cc == NULL) {
    return;
  }
  ConnectClient_set_connected(cc, ConnectClient_get_connected(cc) - 1);
}

/*
 * Function name: ConnectClient_get_listenFdp
 * Description: Get pointer to listen socket descriptor.
 * Arguments: cc - pointer to ConnectClient structure
 * Returns: Pointer to listen socket descriptor.
 */

int*
ConnectClient_get_listenFdp(ConnectClient* cc)
{
  if (cc == NULL) {
    return NULL;
  }
  return (&(cc->listenFd));
}

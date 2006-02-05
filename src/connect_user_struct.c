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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "activefor.h"
#include "connect_user_struct.h"

/*
 * Function name: ConnectUser_new
 * Description: Create and initialize new ConnectUser structure.
 * Returns: Newly created ConnectUser structure.
 */

ConnectUser*
ConnectUser_new()
{
  ConnectUser* tmp = calloc(1, sizeof(ConnectUser));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  tmp->bufList = BufList_new();
  assert(tmp->bufList != NULL);
  if (tmp->bufList == NULL) {
    ConnectUser_free(&tmp);
    return NULL;
  }
  tmp->stats = UserStats_new();
  assert(tmp->stats != NULL);
  if (tmp->stats == NULL) {
    ConnectUser_free(&tmp);
    return NULL;
  }
  return tmp;
}

/*
 * Function name: ConnectUser_free
 * Description: Free the memory allocated for ConnectUser structure.
 * Arguments: cu - pointer to pointer to ConnectUser structure
 */

void
ConnectUser_free(ConnectUser** cu)
{
  BufList* bftmp;
  UserStats* ustmp;
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  assert((*cu) != NULL);
  if ((*cu) == NULL) {
    return;
  }
  bftmp = ConnectUser_get_bufList((*cu));
  ustmp = ConnectUser_get_stats((*cu));
  BufList_free(&bftmp);
  UserStats_free(&ustmp);
  free((*cu));
  (*cu) = NULL;
}

/*
 * Function name: ConnectUser_set_state
 * Description: Set state of the connected user.
 * Arguments: cu - pointer to ConnectUser structure
 *            state - state of the connected User
 */

void
ConnectUser_set_state(ConnectUser* cu, char state)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  cu->state = state;
}

/*
 * Function name: ConnectUser_set_connFd
 * Description: Set connection's file descriptor.
 * Arguments: cu - pointer to ConnectUser structure
 *            connFd - connection's file descriptor
 */

void
ConnectUser_set_connFd(ConnectUser* cu, int connFd)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  cu->connFd = connFd;
}

/*
 * Function name: ConnectUser_set_whatClient
 * Description: Set client number, to which this user is connected to.
 * Arguments: cu - pointer to ConnectUser structure
 *            whatClient - client number, to which this user is connected to
 */

void
ConnectUser_set_whatClient(ConnectUser* cu, int whatClient)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  cu->whatClient = whatClient;
}

/*
 * Function name: ConnectUser_set_userId
 * Description: Set user identification number.
 * Arguments: cu - pointer to ConnectUser structure
 *            userId - user identification number
 */

void
ConnectUser_set_userId(ConnectUser* cu, int userId)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  cu->userId = userId;
}

/*
 * Function name: ConnectUser_set_connectTime
 * Description: Set connect time of the user.
 * Arguments: cu - pointer to ConnectUser structure
 *            connectTime - connect time of the user
 */

void
ConnectUser_set_connectTime(ConnectUser* cu, time_t connectTime)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  cu->connectTime = connectTime;
}

/*
 * Function name: ConnectUser_set_nameBuf
 * Description: Set name of the user.
 * Arguments: cu - pointer to ConnectUser structure
 *            nameBuf - name of the user
 */

void
ConnectUser_set_nameBuf(ConnectUser* cu, char* nameBuf)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  memset(cu->nameBuf, 0, 128);
  strncpy(cu->nameBuf, nameBuf, 127);
}

/*
 * Function name: ConnectUser_set_portBuf
 * Description: Set port from which user is connected.
 * Arguments: cu - pointer to ConnectUser structure
 *            portBuf - port from which user is connected
 */

void
ConnectUser_set_portBuf(ConnectUser* cu, char* portBuf)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  memset(cu->portBuf, 0, 7);
  strncpy(cu->portBuf, portBuf, 6);
}

/*
 * Function name: ConnectUser_set_bufList
 * Description: Set buffer list for incoming packets.
 * Arguments: cu - pointer to ConnectUser structure
 *            bufList - buffer list for incoming packets
 */

void
ConnectUser_set_bufList(ConnectUser* cu, BufList* bufList)
{
  BufList* bftmp;
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  bftmp = ConnectUser_get_bufList(cu);
  BufList_free(&bftmp);
  cu->bufList = bufList;
}

/*
 * Function name: ConnectUser_set_stats
 * Description: Set stats object for this user.
 * Arguments: cu - pointer to ConnectUser structure
 *            stats - stats object for this user
 */

void
ConnectUser_set_stats(ConnectUser* cu, UserStats* stats)
{
  UserStats* ustmp;
  assert(cu != NULL);
  if (cu == NULL) {
    return;
  }
  ustmp = ConnectUser_get_stats(cu);
  UserStats_free(&ustmp);
  cu->stats = stats;
}

/*
 * Function name: ConnectUser_get_state
 * Description: Get state of the connected user.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: State of the connected user.
 */

char
ConnectUser_get_state(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return S_STATE_CLEAR;
  }
  return cu->state;
}

/*
 * Function name: ConnectUser_get_connFd
 * Description: Get connection's file descriptor.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: Connection's file descriptor.
 */

int
ConnectUser_get_connFd(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return -1;
  }
  return cu->connFd;
}

/*
 * Function name: ConnectUser_get_whatClient
 * Description: Get client number, to which this user is connected to.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: Client number, to which this user is connected to.
 */

int
ConnectUser_get_whatClient(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return -1;
  }
  return cu->whatClient;
}

/*
 * Function name: ConnectUser_get_userId
 * Description: Get user identification number.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: User identification number.
 */

int
ConnectUser_get_userId(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return -1;
  }
  return cu->userId;
}

/*
 * Function name: ConnectUser_get_connectTime
 * Description: Get connect time of the user.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: Connect time of the user.
 */

time_t
ConnectUser_get_connectTime(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return 0;
  }
  return cu->connectTime;
}

/*
 * Function name: ConnectUser_get_nameBuf
 * Description: Get name of the user.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: Name of the user.
 */

char*
ConnectUser_get_nameBuf(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return NULL;
  }
  return cu->nameBuf;
}

/*
 * Function name: ConnectUser_get_portBuf
 * Description: Get port from which user is connected.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: Port from which user is connected.
 */

char*
ConnectUser_get_portBuf(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return NULL;
  }
  return cu->portBuf;
}

/*
 * Function name: ConnectUser_get_bufList
 * Description: Get buffer list for incoming packets.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: Buffer list for incoming packets.
 */

BufList*
ConnectUser_get_bufList(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return NULL;
  }
  return cu->bufList;
}

/*
 * Function name: ConnectUser_get_stats
 * Description: Get stats object for this user.
 * Arguments: cu - pointer to ConnectUser structure
 * Returns: Stats object for this user.
 */

UserStats*
ConnectUser_get_stats(ConnectUser* cu)
{
  assert(cu != NULL);
  if (cu == NULL) {
    return NULL;
  }
  return cu->stats;
}

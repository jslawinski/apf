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

#include <stdio.h>
#include <string.h>
#include "clientnames.h"

char*
get_clientname(RealmT* pointer, int client)
{
  static char clientname[10];
  
  if (ConnectClient_get_sClientId(pointer->clitable[client]) == NULL) {
    memset(clientname, 0, 10);
    sprintf(clientname, "%d", ConnectClient_get_clientId(pointer->clitable[client]));
    return clientname;
  }
  
  return ConnectClient_get_sClientId(pointer->clitable[client]);
}

int
get_clientid(RealmT* pointer, char* clientname)
{
  int i, n;
  char guard;
  
  for (i = 0; i < pointer->clinum; ++i) {
    if (ConnectClient_get_sClientId(pointer->clitable[i]) != NULL) {
      if (strcmp(clientname, ConnectClient_get_sClientId(pointer->clitable[i])) == 0) {
        return ConnectClient_get_clientId(pointer->clitable[i]);
      }
    }
  }

  if (sscanf(clientname, "%d%c", &i, &guard) == 1) {
    n = get_clientnumber(pointer, i);
    if ((n >= 0) && (n < pointer->clinum)) {
      if (ConnectClient_get_sClientId(pointer->clitable[n]) == NULL) {
        return i;
      }
    }
  }
  return -1;
}

int
get_clientnumber(RealmT* pointer, int clientid)
{
  int i;
  for (i = 0; i < pointer->clinum; ++i) {
    if (ConnectClient_get_clientId(pointer->clitable[i]) == clientid) {
      return i;
    }
  }

  return -1;
}

char*
get_raclientname(RealmT* pointer, int client)
{
  static char clientname[10];
  
  if (ConnectClient_get_sClientId(pointer->raclitable[client]) == NULL) {
    memset(clientname, 0, 10);
    sprintf(clientname, "%d", ConnectClient_get_clientId(pointer->raclitable[client]));
    return clientname;
  }
  
  return ConnectClient_get_sClientId(pointer->raclitable[client]);
}

int
get_raclientid(RealmT* pointer, char* clientname)
{
  int i, n;
  char guard;
  
  for (i = 0; i < pointer->raclinum; ++i) {
    if (ConnectClient_get_sClientId(pointer->raclitable[i]) != NULL) {
      if (strcmp(clientname, ConnectClient_get_sClientId(pointer->raclitable[i])) == 0) {
        return ConnectClient_get_clientId(pointer->raclitable[i]);
      }
    }
  }

  if (sscanf(clientname, "%d%c", &i, &guard) == 1) {
    n = get_raclientnumber(pointer, i);
    if ((n >= 0) && (n < pointer->raclinum)) {
      if (ConnectClient_get_sClientId(pointer->raclitable[n]) == NULL) {
        return i;
      }
    }
  }
  
  return -1;
}

int
get_raclientnumber(RealmT* pointer, int clientid)
{
  int i;
  for (i = 0; i < pointer->raclinum; ++i) {
    if (ConnectClient_get_clientId(pointer->raclitable[i]) == clientid) {
      return i;
    }
  }

  return -1;
}

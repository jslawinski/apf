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

#include <stdio.h>
#include <string.h>
#include "clientnames.h"

char*
get_clientname(ServerRealm* pointer, int client)
{
  static char clientname[10];
  
  if (ConnectClient_get_sClientId(ServerRealm_get_clientsTable(pointer)[client]) == NULL) {
    memset(clientname, 0, 10);
    sprintf(clientname, "%d", ConnectClient_get_clientId(ServerRealm_get_clientsTable(pointer)[client]));
    return clientname;
  }
  
  return ConnectClient_get_sClientId(ServerRealm_get_clientsTable(pointer)[client]);
}

int
get_clientid(ServerRealm* pointer, char* clientname)
{
  int i, n;
  char guard;
  
  for (i = 0; i < ServerRealm_get_clientsLimit(pointer); ++i) {
    if (ConnectClient_get_sClientId(ServerRealm_get_clientsTable(pointer)[i]) != NULL) {
      if (strcmp(clientname, ConnectClient_get_sClientId(ServerRealm_get_clientsTable(pointer)[i])) == 0) {
        return ConnectClient_get_clientId(ServerRealm_get_clientsTable(pointer)[i]);
      }
    }
  }

  if (sscanf(clientname, "%d%c", &i, &guard) == 1) {
    n = get_clientnumber(pointer, i);
    if ((n >= 0) && (n < ServerRealm_get_clientsLimit(pointer))) {
      if (ConnectClient_get_sClientId(ServerRealm_get_clientsTable(pointer)[n]) == NULL) {
        return i;
      }
    }
  }
  return -1;
}

int
get_clientnumber(ServerRealm* pointer, int clientid)
{
  int i;
  for (i = 0; i < ServerRealm_get_clientsLimit(pointer); ++i) {
    if (ConnectClient_get_clientId(ServerRealm_get_clientsTable(pointer)[i]) == clientid) {
      return i;
    }
  }

  return -1;
}

char*
get_raclientname(ServerRealm* pointer, int client)
{
  static char clientname[10];
  
  if (ConnectClient_get_sClientId(ServerRealm_get_raClientsTable(pointer)[client]) == NULL) {
    memset(clientname, 0, 10);
    sprintf(clientname, "%d", ConnectClient_get_clientId(ServerRealm_get_raClientsTable(pointer)[client]));
    return clientname;
  }
  
  return ConnectClient_get_sClientId(ServerRealm_get_raClientsTable(pointer)[client]);
}

int
get_raclientid(ServerRealm* pointer, char* clientname)
{
  int i, n;
  char guard;
  
  for (i = 0; i < ServerRealm_get_raClientsLimit(pointer); ++i) {
    if (ConnectClient_get_sClientId(ServerRealm_get_raClientsTable(pointer)[i]) != NULL) {
      if (strcmp(clientname, ConnectClient_get_sClientId(ServerRealm_get_raClientsTable(pointer)[i])) == 0) {
        return ConnectClient_get_clientId(ServerRealm_get_raClientsTable(pointer)[i]);
      }
    }
  }

  if (sscanf(clientname, "%d%c", &i, &guard) == 1) {
    n = get_raclientnumber(pointer, i);
    if ((n >= 0) && (n < ServerRealm_get_raClientsLimit(pointer))) {
      if (ConnectClient_get_sClientId(ServerRealm_get_raClientsTable(pointer)[n]) == NULL) {
        return i;
      }
    }
  }
  
  return -1;
}

int
get_raclientnumber(ServerRealm* pointer, int clientid)
{
  int i;
  for (i = 0; i < ServerRealm_get_raClientsLimit(pointer); ++i) {
    if (ConnectClient_get_clientId(ServerRealm_get_raClientsTable(pointer)[i]) == clientid) {
      return i;
    }
  }

  return -1;
}

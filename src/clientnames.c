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

#include <stdio.h>
#include <string.h>
#include "clientnames.h"

char*
get_clientname(RealmT* pointer, int client)
{
  static char clientname[10];
  
  if (pointer->clitable[client].clientid == NULL) {
    memset(clientname, 0, 10);
    sprintf(clientname, "%d", pointer->clitable[client].clientnum);
    return clientname;
  }
  
  return pointer->clitable[client].clientid;
}

int
get_clientid(RealmT* pointer, char* clientname)
{
  int i, n;
  char guard;
  
  for (i = 0; i < pointer->clinum; ++i) {
    if (pointer->clitable[i].clientid != NULL) {
      if (strcmp(clientname, pointer->clitable[i].clientid) == 0) {
        return pointer->clitable[i].clientnum;
      }
    }
  }

  if (sscanf(clientname, "%d%c", &i, &guard) == 1) {
    n = get_clientnumber(pointer, i);
    if ((n >= 0) && (n < pointer->clinum)) {
      if (pointer->clitable[n].clientid == NULL) {
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
    if (pointer->clitable[i].clientnum == clientid) {
      return i;
    }
  }

  return -1;
}

char*
get_raclientname(RealmT* pointer, int client)
{
  static char clientname[10];
  
  if (pointer->raclitable[client].clientid == NULL) {
    memset(clientname, 0, 10);
    sprintf(clientname, "%d", pointer->raclitable[client].clientnum);
    return clientname;
  }
  
  return pointer->raclitable[client].clientid;
}

int
get_raclientid(RealmT* pointer, char* clientname)
{
  int i, n;
  char guard;
  
  for (i = 0; i < pointer->raclinum; ++i) {
    if (pointer->raclitable[i].clientid != NULL) {
      if (strcmp(clientname, pointer->raclitable[i].clientid) == 0) {
        return pointer->raclitable[i].clientnum;
      }
    }
  }

  if (sscanf(clientname, "%d%c", &i, &guard) == 1) {
    n = get_raclientnumber(pointer, i);
    if ((n >= 0) && (n < pointer->raclinum)) {
      if (pointer->raclitable[n].clientid == NULL) {
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
    if (pointer->raclitable[i].clientnum == clientid) {
      return i;
    }
  }

  return -1;
}

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
#include <assert.h>
#include <string.h>

#include "server_find.h"

/*
 * Function name: find_client
 * Description: Returns the client number with free user slots.
 * Arguments: ptr - the server realm
 *            mode - the strategy of client choosing
 *            usrclipair - the number of usrclipair
 * Returns: The client number with free user slots.
 */

int
find_client(ServerRealm* ptr, char mode, int usrclipair)
{
  int i;
  assert(ptr != NULL);
  switch(mode) {
    case 1: { /* fill first client before go to next */
              for (i = 0; i < ServerRealm_get_clientsLimit(ptr); ++i) {
                if ((ConnectClient_get_state(ServerRealm_get_clientsTable(ptr)[i]) ==
                      CONNECTCLIENT_STATE_ACCEPTED) &&
                    (ConnectClient_get_usrCliPair(ServerRealm_get_clientsTable(ptr)[i]) == usrclipair)) {
                  if (ConnectClient_get_connected(ServerRealm_get_clientsTable(ptr)[i]) <
                      ConnectClient_get_limit(ServerRealm_get_clientsTable(ptr)[i])) {
                    return i;
                  }
                }
              }
              break;
            }
    default: {
               return 0;
             }
  }
  return 0;
}

/*
 * Function name: find_usernum
 * Description: Finds the free user slot, fill it and returns its number.
 * Arguments: ptr - the connected client
 *            usernum - the connection number on the afserver
 * Returns: The user number in the connected client on the afserver side.
 */

int
find_usernum(ConnectClient* ptr, int usernum)
{
  int i;
  assert(ptr != NULL);
  for (i = 0; i < ConnectClient_get_limit(ptr); ++i) {
    if (ConnectClient_get_users(ptr)[i] == -1) {
      ConnectClient_get_users(ptr)[i] = usernum;
      return i;
    }
  }
  return -1;
}

/*
 * Function name: find_previousFd
 * Description: Finds the file descriptor bound previously to the given
 *              host:serv.
 * Arguments: table - the table of UsrCli structures
 *            index - the current index of the search
 *            host - the name of the host
 *            serv - the name of the service (port)
 * Returns: The previously bound file descriptor.
 */

int
find_previousFd(UsrCli** table, int index, char* host, char* serv)
{
  int i;
  assert(table != NULL);
  assert(index >= 0);
  for (i = 0; i < index; ++i) {
    
    if (UsrCli_get_manageHostName(table[i])) {
      if (host) {
        if (strcmp(UsrCli_get_listenHostName(table[i]), host)) {
          continue;
        }
      }
      else {
        continue;
      }
    }
    else {
      if (host) {
        continue;
      }
    }

    if (UsrCli_get_managePortName(table[i])) {
      if (serv) {
        if (strcmp(UsrCli_get_managePortName(table[i]), serv)) {
          continue;
        }
      }
      else {
        continue;
      }
    }
    else {
      if (serv) {
        continue;
      }
    }

    return UsrCli_get_manageFd(table[i]);
  }
  return -1;
}

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

#include "server_eval.h"

/*
 * Function name: eval_numofcon
 * Description: Returns the real connection number on the afserver.
 * Arguments: ptr - the server realm
 *            client - client number
 *            numofcon - the connection number on the afclient
 * Returns: The real connection number on the afserver.
 */

int
eval_numofcon(ServerRealm* ptr, int client, int numofcon)
{
  assert(ptr != NULL);
  if ((numofcon >= 0) && (numofcon < ConnectClient_get_limit(ServerRealm_get_clientsTable(ptr)[client]))) {
    numofcon = ConnectClient_get_users(ServerRealm_get_clientsTable(ptr)[client])[numofcon];
  }
  else {
    numofcon = -1;
  }
  return numofcon;
}

/*
 * Function name: eval_usernum
 * Description: Returns the user number in the connected client on the afserver side.
 * Arguments: ptr - the connected client
 *            usernum - the connection number on the afserver
 * Returns: The user number in the connected client on the afserver side.
 */

int
eval_usernum(ConnectClient* ptr, int usernum)
{
  int i;
  assert(ptr != NULL);
  for (i = 0; i < ConnectClient_get_limit(ptr); ++i) {
    if (ConnectClient_get_users(ptr)[i] == usernum)
      return i;
  }
  return -1;
}

/*
 * Function name: eval_UsrCliPair
 * Description: Returns how many UsrCli structures are connected with the current manage port.
 * Arguments: table - the table of UsrCli structures
 *            index - the current index of the evaluation
 *            host - the name of the host
 *            serv - the name of the service (port)
 * Returns: How many UsrCli structures are connected with the current manage port.
 */

int
eval_UsrCliPair(UsrCli** table, int index, char* host, char* serv)
{
  int i;
  int result = 0;
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

    result++;
  }
  return result;
}

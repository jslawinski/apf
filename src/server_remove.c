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

#include <assert.h>

#include "server_remove.h"

/*
 * Function name: remove_client
 * Description: Removes the client.
 * Arguments: ptr - the server realm
 *            client - the client number
 *            set - the set of file descriptors for reading
 *            wset - the set of file descriptors for writing
 *            scheduler - the task scheduler
 */

void
remove_client(ServerRealm* ptr, int client, fd_set* set, fd_set* wset, TaskScheduler* scheduler)
{
  int i;
  Task* task;
  
  assert(ptr != NULL);
  assert(client >= 0);
  assert(set != NULL);
  assert(wset != NULL);
  
  if (ConnectClient_get_state(ServerRealm_get_clientsTable(ptr)[client]) == CONNECTCLIENT_STATE_ACCEPTED) {
    for (i = 0; i < ServerRealm_get_usersLimit(ptr); ++i) {
      if (ConnectUser_get_whatClient(ServerRealm_get_usersTable(ptr)[i]) == client) {
        if (ConnectUser_get_state(ServerRealm_get_usersTable(ptr)[i]) != S_STATE_CLEAR) {
          ConnectUser_set_state(ServerRealm_get_usersTable(ptr)[i], S_STATE_CLEAR);
          FD_CLR(ConnectUser_get_connFd(ServerRealm_get_usersTable(ptr)[i]), set);
          FD_CLR(ConnectUser_get_connFd(ServerRealm_get_usersTable(ptr)[i]), wset);
          close(ConnectUser_get_connFd(ServerRealm_get_usersTable(ptr)[i]));
          ServerRealm_decrease_connectedUsers(ptr);
        }
      }
    }
  }
  for (i = 0; i < ConnectClient_get_limit(ServerRealm_get_clientsTable(ptr)[client]); ++i) {
    ConnectClient_get_users(ServerRealm_get_clientsTable(ptr)[client])[i] = -1;
  }
  if ((ServerRealm_get_clientsLimit(ptr) != client) && (ServerRealm_get_basePortOn(ptr) == 1)) {
    close(ConnectClient_get_listenFd(ServerRealm_get_clientsTable(ptr)[client]));
    FD_CLR(ConnectClient_get_listenFd(ServerRealm_get_clientsTable(ptr)[client]), set);
  }
  ConnectClient_set_sClientId(ServerRealm_get_clientsTable(ptr)[client], NULL);
  ConnectClient_set_connected(ServerRealm_get_clientsTable(ptr)[client], 0);
  close(SslFd_get_fd(ConnectClient_get_sslFd(ServerRealm_get_clientsTable(ptr)[client])));
  FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(ServerRealm_get_clientsTable(ptr)[client])), set);
  if (scheduler) {
    if ((task = ConnectClient_get_task(ServerRealm_get_clientsTable(ptr)[client]))) {
      TaskScheduler_removeTask(scheduler, task);
      ConnectClient_set_task(ServerRealm_get_clientsTable(ptr)[client], NULL);
    }
  }
  SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(ServerRealm_get_clientsTable(ptr)[client])));
  ConnectClient_set_state(ServerRealm_get_clientsTable(ptr)[client], CONNECTCLIENT_STATE_FREE);
  ServerRealm_decrease_connectedClients(ptr);
}

/*
 * Function name: remove_raclient
 * Description: Removes the remote admin client.
 * Arguments: ptr - the server realm
 *            client - the client number
 *            set - the set of file descriptors for reading
 *            wset - the set of file descriptors for writing
 *            scheduler - the task scheduler
 */

void
remove_raclient(ServerRealm* ptr, int client, fd_set* set, fd_set* wset, TaskScheduler* scheduler)
{
  int i;
  Task* task;
  
  assert(ptr != NULL);
  assert(client >= 0);
  assert(set != NULL);
  assert(wset != NULL);
  
  for (i = 0; i < ConnectClient_get_limit(ServerRealm_get_raClientsTable(ptr)[client]); ++i) {
    ConnectClient_get_users(ServerRealm_get_raClientsTable(ptr)[client])[i] = -1;
  }
  ConnectClient_set_sClientId(ServerRealm_get_raClientsTable(ptr)[client], NULL);
  ConnectClient_set_connected(ServerRealm_get_raClientsTable(ptr)[client], 0);
  close(SslFd_get_fd(ConnectClient_get_sslFd(ServerRealm_get_raClientsTable(ptr)[client])));
  FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(ServerRealm_get_raClientsTable(ptr)[client])), set);
  if (scheduler) {
    if ((task = ConnectClient_get_task(ServerRealm_get_raClientsTable(ptr)[client]))) {
      TaskScheduler_removeTask(scheduler, task);
      ConnectClient_set_task(ServerRealm_get_raClientsTable(ptr)[client], NULL);
    }
  }
  SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(ServerRealm_get_raClientsTable(ptr)[client])));
  ServerRealm_decrease_connectedClients(ptr);
  if (ConnectClient_get_state(ServerRealm_get_raClientsTable(ptr)[client]) == CONNECTCLIENT_STATE_ACCEPTED) {
    ServerRealm_decrease_connectedRaClients(ptr);
  }
  ConnectClient_set_state(ServerRealm_get_raClientsTable(ptr)[client], CONNECTCLIENT_STATE_FREE);
}

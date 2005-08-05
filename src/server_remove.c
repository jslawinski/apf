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

#include "server_remove.h"

void
remove_client(RealmT* ptr, int client, fd_set* set, fd_set* wset, int* con)
{
  int i;
  if (ConnectClient_get_state(ptr->clitable[client]) == CONNECTCLIENT_STATE_ACCEPTED) {
    for (i = 0; i < ptr->usernum; ++i) {
      if (ConnectUser_get_whatClient(ptr->contable[i]) == client) {
        if (ConnectUser_get_state(ptr->contable[i]) != S_STATE_CLEAR) {
          ConnectUser_set_state(ptr->contable[i], S_STATE_CLEAR);
          FD_CLR(ConnectUser_get_connFd(ptr->contable[i]), set);
          FD_CLR(ConnectUser_get_connFd(ptr->contable[i]), wset);
          close(ConnectUser_get_connFd(ptr->contable[i]));
          ptr->usercon--;
        }
      }
    }
  }
  for (i = 0; i < ConnectClient_get_limit(ptr->clitable[client]); ++i) {
    ConnectClient_get_users(ptr->clitable[client])[i] = -1;
  }
  if ((ptr->clinum != client) && (ptr->baseport == 1)) {
    close(ConnectClient_get_listenFd(ptr->clitable[client]));
    FD_CLR(ConnectClient_get_listenFd(ptr->clitable[client]), set);
  }
  ConnectClient_set_sClientId(ptr->clitable[client], NULL);
  ConnectClient_set_connected(ptr->clitable[client], 0);
  close(SslFd_get_fd(ConnectClient_get_sslFd(ptr->clitable[client])));
  FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(ptr->clitable[client])), set);
  if (ConnectClient_get_state(ptr->clitable[client]) == CONNECTCLIENT_STATE_AUTHORIZING) {
    (*con)--;
  }
  SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(ptr->clitable[client])));
  ConnectClient_set_state(ptr->clitable[client], CONNECTCLIENT_STATE_FREE);
  ptr->clicon--;
}

void
remove_raclient(RealmT* ptr, int client, fd_set* set, fd_set* wset, int* con)
{
  int i;
  for (i = 0; i < ConnectClient_get_limit(ptr->raclitable[client]); ++i) {
    ConnectClient_get_users(ptr->raclitable[client])[i] = -1;
  }
  ConnectClient_set_sClientId(ptr->raclitable[client], NULL);
  ConnectClient_set_connected(ptr->raclitable[client], 0);
  close(SslFd_get_fd(ConnectClient_get_sslFd(ptr->raclitable[client])));
  FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(ptr->raclitable[client])), set);
  if (ConnectClient_get_state(ptr->raclitable[client]) == CONNECTCLIENT_STATE_AUTHORIZING) {
    (*con)--;
  }
  SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(ptr->raclitable[client])));
  ptr->clicon--;
  if (ConnectClient_get_state(ptr->raclitable[client]) == CONNECTCLIENT_STATE_ACCEPTED) {
    ptr->raclicon--;
  }
  ConnectClient_set_state(ptr->raclitable[client], CONNECTCLIENT_STATE_FREE);
}

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
  if (ptr->clitable[client].ready == 3) {
    for (i = 0; i < ptr->usernum; ++i) {
      if (ptr->contable[i].whatcli == client) {
        if (ptr->contable[i].state != S_STATE_CLEAR) {
          ptr->contable[i].state = S_STATE_CLEAR;
          FD_CLR(ptr->contable[i].connfd, set);
          FD_CLR(ptr->contable[i].connfd, wset);
          close(ptr->contable[i].connfd);
          ptr->usercon--;
        }
      }
    }
  }
  for (i=0; i<ptr->clitable[client].usernum; ++i) {
    ptr->clitable[client].users[i] = -1;
  }
  if ((ptr->clinum != client) && (ptr->baseport == 1)) {
    close(ptr->clitable[client].listenfd);
    FD_CLR(ptr->clitable[client].listenfd, set);
  }
  if (ptr->clitable[client].clientid) {
    free(ptr->clitable[client].clientid);
    ptr->clitable[client].clientid = NULL;
  }
  ptr->clitable[client].usercon = 0;
  close(ptr->clitable[client].cliconn.commfd);
  FD_CLR(ptr->clitable[client].cliconn.commfd, set);
  if (ptr->clitable[client].ready == 2)
    (*con)--;
  SSL_clear(ptr->clitable[client].cliconn.ssl);
  ptr->clitable[client].ready = 0;
  ptr->clicon--;
}

void
remove_raclient(RealmT* ptr, int client, fd_set* set, fd_set* wset, int* con)
{
  int i;
  for (i=0; i<ptr->raclitable[client].usernum; ++i) {
    ptr->raclitable[client].users[i] = -1;
  }
  if (ptr->raclitable[client].clientid) {
    free(ptr->raclitable[client].clientid);
    ptr->raclitable[client].clientid = NULL;
  }
  ptr->raclitable[client].usercon = 0;
  close(ptr->raclitable[client].cliconn.commfd);
  FD_CLR(ptr->raclitable[client].cliconn.commfd, set);
  if (ptr->raclitable[client].ready == 2) {
    (*con)--;
  }
  SSL_clear(ptr->raclitable[client].cliconn.ssl);
  ptr->clicon--;
  if (ptr->raclitable[client].ready == 3) {
    ptr->raclicon--;
  }
  ptr->raclitable[client].ready = 0;
}

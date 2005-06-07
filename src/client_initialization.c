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

#include "client_initialization.h"
#include "network.h"

int
initialize_client_stage1(char tunneltype, clifd* master, char* name, char* manage,
    char* proxyname, char* proxyport, char ipfam, SSL_CTX* ctx, unsigned char* buff, unsigned char* pass,
    char wanttoexit)
{
  int n;
  switch (tunneltype) {
    case 0: {
      if (ip_connect(&(master->commfd), name, manage, ipfam)) {
#ifdef AF_INET6
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "tcp_connect_%s error for %s, %s",
            (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec", name, manage);
#else
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "tcp_connect error for %s, %s", name, manage);
#endif
        if (wanttoexit) {
          exit(1);
        }
        else {
          return 1;
        }
      } 
      break;
            }
#ifdef HAVE_LIBPTHREAD 
    case 1: {
      if (initialize_http_proxy_client(&(master->commfd), name, manage, proxyname, proxyport, ipfam)) {
#ifdef AF_INET6
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "http_proxy_connect_%s error for %s, %s (proxy: %s, %s)",
            (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec", name, manage, proxyname, proxyport);
#else 
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "http_proxy_connect error for %s, %s (proxy: %s, %s)", name, manage, proxyname, proxyport);
#endif 
        if (wanttoexit) {
          exit(1);
        }
        else {
          return 1;
        }
      }
      break;
            }
#endif
    default: {
               aflog(LOG_T_INIT, LOG_I_CRIT,
                   "Unknown tunnel type");
               if (wanttoexit) {
                 exit(1);
               }
               else {
                 return 1;
               }
               break;
             }
  }
  master->ssl = SSL_new(ctx);
  if (SSL_set_fd(master->ssl, master->commfd) != 1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Problem with initializing ssl... exiting");
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 2;
    }
  }

  aflog(LOG_T_INIT, LOG_I_INFO,
      "Trying SSL_connect");
  if ((n = SSL_connect(master->ssl)) == 1) {
    aflog(LOG_T_INIT, LOG_I_INFO,
        "SSL_connect successful");
  }
  else {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "SSL_connect has failed (%d)... exiting", n);
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 3;
    }
  }

  buff[0] = AF_S_LOGIN;
  buff[1] = pass[0];
  buff[2] = pass[1];
  buff[3] = pass[2];
  buff[4] = pass[3];

  return 0;
}

int
initialize_client_stage2(char *type, clifd* master, int* usernum, unsigned char* buff, char wanttoexit)
{
  send_message(*type, *master, buff, 5);
  buff[0] = 0;
  get_message(*type, *master, buff, -5);

  if ( buff[0] == 0 ) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Connection with afserver failed");
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 1;
    }
  }
  if ( buff[0] == AF_S_WRONG ) {
    aflog(LOG_T_INIT, LOG_I_ERR,
        "Wrong password");
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 1;
    }
  }
  if ( buff[0] == AF_S_CANT_OPEN ) {
    aflog(LOG_T_INIT, LOG_I_ERR,
        "Server is full");
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 1;
    }
  }
  if ( buff[0] != AF_S_LOGIN ) {
    aflog(LOG_T_INIT, LOG_I_ERR,
        "Incompatible server type or server full");
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 1;
    }
  }

  *type = buff[3];
  (*usernum) = buff[1];
  (*usernum) = (*usernum) << 8;
  (*usernum) += buff[2];
  return 0;
}

int
initialize_client_stage3(ConnectuserT** contable, clifd* master, int usernum, int* buflength, socklen_t* len,
    fd_set* allset, fd_set* wset, int* maxfdp1, char wanttoexit)
{
  (*contable) = calloc( usernum, sizeof(ConnectuserT));
  if ((*contable) == NULL) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Calloc error - unable to successfully communicate with server");
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 1;
    }
  }

  (*len) = 4;
  if (getsockopt(master->commfd, SOL_SOCKET, SO_SNDBUF, buflength, len) == -1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Can't get socket send buffer size - exiting...");
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 2;
    }
  }
  
  FD_ZERO(allset);
  FD_ZERO(wset);

  FD_SET(master->commfd, allset);
  (*maxfdp1) = master->commfd + 1;
  return 0;
}

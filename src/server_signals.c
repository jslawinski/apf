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

#include <config.h>

#include "server_signals.h"
#include "activefor.h"
#include "thread_management.h"
#include "http_proxy_functions.h"
#include "stats.h"
#include "logging.h"
#include "server_configuration_struct.h"

extern ServerConfiguration* config;

/*
 * Function name: server_sig_int
 * Description: Function responsible for handling SIG_INT.
 * Arguments: signo - the signal number
 */

void
server_sig_int(int signo)
{
  int i, j;
  unsigned char buff[5];
  ServerRealm** scRealmsTable;
  
#ifdef HAVE_LIBPTHREAD
  if (!is_this_a_mainthread()) {
    return;
  }
#endif

  for (j = 0; j < ServerConfiguration_get_realmsNumber(config); ++j) {
    scRealmsTable = ServerConfiguration_get_realmsTable(config);
    buff[0] = AF_S_CLOSING; /* closing */
    for (i = 0; i < ServerRealm_get_clientsLimit(scRealmsTable[j]); ++i) {
      if (ConnectClient_get_state(ServerRealm_get_clientsTable(scRealmsTable[j])[i]) ==
          CONNECTCLIENT_STATE_ACCEPTED) {
        SslFd_send_message(ServerRealm_get_realmType(scRealmsTable[j]),
            ConnectClient_get_sslFd(
              ServerRealm_get_clientsTable(scRealmsTable[j])[i]),
            buff, 5);
        close(SslFd_get_fd(ConnectClient_get_sslFd(
                ServerRealm_get_clientsTable(scRealmsTable[j])[i])));
      }
    }
    for (i = 0; i < ServerRealm_get_raClientsLimit(scRealmsTable[j]); ++i) {
      if (ConnectClient_get_state(ServerRealm_get_raClientsTable(scRealmsTable[j])[i]) ==
          CONNECTCLIENT_STATE_ACCEPTED) {
        SslFd_send_message(ServerRealm_get_realmType(scRealmsTable[j]) | TYPE_SSL,
            ConnectClient_get_sslFd(
              ServerRealm_get_raClientsTable(scRealmsTable[j])[i]),
            buff, 5);
        close(SslFd_get_fd(ConnectClient_get_sslFd(ServerRealm_get_raClientsTable(scRealmsTable[j])[i])));
      }
    }

  }

  /* FIXME: give a time to close all connections */
  mysleep(0.1);

  aflog(LOG_T_MAIN, LOG_I_NOTICE,
      "SERVER CLOSED cg: %ld bytes", getcg());
  exit(0);
}


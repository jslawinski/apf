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

#include <stdlib.h>
#include <assert.h>

#include "logging.h"
#include "realmnames.h"
#include "clientnames.h"
#include "server_remove.h"
#include "remove_client_task.h"

/*
 * Function name: RCTdata_new
 * Description: Creates and initializes new data for remove client task.
 * Arguments: config - server configuration
 *            realm - the realm id
 *            client - the client id
 *            ra - if the client is in remote administration mode
 *            fdset - the descriptor set watched for read
 * Returns: Pointer to newly created RCTdata structure.
 */

RCTdata*
RCTdata_new(ServerConfiguration* config, int realm, int client, char ra, char reason, fd_set* set, fd_set* wset)
{
  RCTdata* tmp;
  assert(config != NULL);
  if (config == NULL) {
    return NULL;
  }
  tmp = calloc(1, sizeof(RCTdata));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  tmp->config = config;
  tmp->realm = realm;
  tmp->client = client;
  tmp->ra = ra;
  tmp->reason = reason;
  tmp->set = set;
  tmp->wset = wset;

  return tmp;
}

/*
 * Function name: RCTdata_free
 * Description: Frees the memory allocated for RCTdata structure.
 * Arguments: ptr - pointer to pointer to RCTdata structure
 */

void
RCTdata_free(void** ptr)
{
  RCTdata** data = (RCTdata**) ptr;
  assert(data != NULL);
  if (data == NULL) {
    return;
  }
  assert((*data) != NULL);
  if ((*data) == NULL) {
    return;
  }
  free((*data));
  (*data) = NULL;
}

/*
 * Function name: RCTfunction
 * Description: Function executed in the task by the task scheduler.
 * Arguments: Pointer to the memory containing RCTdata structure.
 */

void
RCTfunction(void* data)
{
  ConnectClient** clientsTable;
  ServerRealm** realmsTable;
  RCTdata* ptr;
  assert(data != NULL);
  if (data == NULL) {
    return;
  }
  ptr = (RCTdata*) data;
  realmsTable = ServerConfiguration_get_realmsTable(ptr->config);
  if (ptr->ra) {
    clientsTable = ServerRealm_get_raClientsTable(realmsTable[ptr->realm]);
  }
  else {
    clientsTable = ServerRealm_get_clientsTable(realmsTable[ptr->realm]);
  }
  switch (ptr->reason) {
    case RCT_REASON_TIMEOUT:
      close(SslFd_get_fd(ConnectClient_get_sslFd(clientsTable[ptr->client])));
      FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(clientsTable[ptr->client])), ptr->set);
      SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(clientsTable[ptr->client])));
      ConnectClient_set_state(clientsTable[ptr->client], CONNECTCLIENT_STATE_FREE);
      ServerRealm_decrease_connectedClients(realmsTable[ptr->realm]);
      aflog(LOG_T_CLIENT, LOG_I_WARNING,
          "realm[%s]: Client[%s]%s: SSL_accept failed (timeout)",
          get_realmname(ptr->config, ptr->realm),
          ptr->ra ? get_raclientname(realmsTable[ptr->realm], ptr->client) :
          get_clientname(realmsTable[ptr->realm], ptr->client),
          ptr->ra ? " (ra)" : "");
      break;
    case RCT_REASON_MAXIDLE:
      aflog(LOG_T_CLIENT, LOG_I_WARNING,
          "realm[%s]: Client[%s]: too long idle --> DROPPING", get_realmname(ptr->config, ptr->realm),
          get_clientname(realmsTable[ptr->realm], ptr->client));
      remove_client(realmsTable[ptr->realm], ptr->client, ptr->set, ptr->wset, NULL);
  }
  ConnectClient_set_task(clientsTable[ptr->client], NULL);
}

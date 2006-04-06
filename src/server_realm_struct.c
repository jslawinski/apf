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
#include <string.h>
#include <assert.h>

#include "string_functions.h"
#include "server_realm_struct.h"

/*
 * Function name: ServerRealm_new
 * Description: Create and initialize new ServerRealm structure.
 * Returns: Pointer to newly created ServerRealm structure.
 */

ServerRealm*
ServerRealm_new()
{
  ServerRealm* tmp = calloc(1, sizeof(ServerRealm));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  tmp->password[0] = 1;
  tmp->password[1] = 2;
  tmp->password[2] = 3;
  tmp->password[3] = 4;
  return tmp;
}

/*
 * Function name: ServerRealm_free
 * Description: Free the memory allocated for ServerRealm structure.
 * Arguments: sr - pointer to pointer to ServerRealm structure
 */

void
ServerRealm_free(ServerRealm** sr)
{
  int i;
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  assert((*sr) != NULL);
  if ((*sr) == NULL) {
    return;
  }
  if ((*sr)->hostName) {
    free((*sr)->hostName);
    (*sr)->hostName = NULL;
  }
  if ((*sr)->sUsersLimit) {
    free((*sr)->sUsersLimit);
    (*sr)->sUsersLimit = NULL;
  }
  if ((*sr)->sClientsLimit) {
    free((*sr)->sClientsLimit);
    (*sr)->sClientsLimit = NULL;
  }
  if ((*sr)->sRaClientsLimit) {
    free((*sr)->sRaClientsLimit);
    (*sr)->sRaClientsLimit = NULL;
  }
  if ((*sr)->sUsersPerClient) {
    free((*sr)->sUsersPerClient);
    (*sr)->sUsersPerClient = NULL;
  }
  if ((*sr)->sClientMode) {
    free((*sr)->sClientMode);
    (*sr)->sClientMode = NULL;
  }
  if ((*sr)->sTimeout) {
    free((*sr)->sTimeout);
    (*sr)->sTimeout = NULL;
  }
  if ((*sr)->realmName) {
    free((*sr)->realmName);
    (*sr)->realmName = NULL;
  }
  if ((*sr)->clientAddress) {
    free((*sr)->clientAddress);
    (*sr)->clientAddress = NULL;
  }
  if ((*sr)->usersTable) {
    for (i = 0; i < (*sr)->usersLimit; ++i) {
      if ((*sr)->usersTable[i]) {
        ConnectUser_free(&((*sr)->usersTable[i]));
      }
    }
    free((*sr)->usersTable);
    (*sr)->usersTable = NULL;
  }
  if ((*sr)->clientsTable) {
    for (i = 0; i < (*sr)->clientsLimit; ++i) {
      if ((*sr)->clientsTable[i]) {
        ConnectClient_free(&((*sr)->clientsTable[i]));
      }
    }
    free((*sr)->clientsTable);
    (*sr)->clientsTable = NULL;
  }
  if ((*sr)->raClientsTable) {
    for (i = 0; i < (*sr)->raClientsLimit; ++i) {
      if ((*sr)->raClientsTable[i]) {
        ConnectClient_free(&((*sr)->raClientsTable[i]));
      }
    }
    free((*sr)->raClientsTable);
    (*sr)->raClientsTable = NULL;
  }
  if ((*sr)->usersClientsTable) {
    for (i = 0; i < (*sr)->userClientPairs; ++i) {
      if ((*sr)->usersClientsTable[i]) {
        UsrCli_free(&((*sr)->usersClientsTable[i]));
      }
    }
    free((*sr)->usersClientsTable);
    (*sr)->usersClientsTable = NULL;
  }
  free((*sr));
  (*sr) = NULL;
}

/*
 * Function name: ServerRealm_set_hostName
 * Description: Set realm's host name.
 * Arguments: sr - pointer to ServerRealm structure
 *            hostName - realm's host name
 */

void
ServerRealm_set_hostName(ServerRealm* sr, char* hostName)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->hostName), hostName);
}

/*
 * Function name: ServerRealm_set_sUsersLimit
 * Description: Set users limit description.
 * Arguments: sr - pointer to ServerRealm structure
 *            sUsersLimit - users limit description
 */

void
ServerRealm_set_sUsersLimit(ServerRealm* sr, char* sUsersLimit)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->sUsersLimit), sUsersLimit);
}

/*
 * Function name: ServerRealm_set_sClientsLimit
 * Description: Set clients limit description.
 * Arguments: sr - pointer to ServerRealm structure
 *            sClientsLimit - clients limit description
 */

void
ServerRealm_set_sClientsLimit(ServerRealm* sr, char* sClientsLimit)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->sClientsLimit), sClientsLimit);
}

/*
 * Function name: ServerRealm_set_sRaClientsLimit
 * Description: Set raClients limit description.
 * Arguments: sr - pointer to ServerRealm structure
 *            sRaClientsLimit - raClients limit description
 */

void
ServerRealm_set_sRaClientsLimit(ServerRealm* sr, char* sRaClientsLimit)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->sRaClientsLimit), sRaClientsLimit);
}

/*
 * Function name: ServerRealm_set_sUsersPerClient
 * Description: Set users per client description.
 * Arguments: sr - pointer to ServerRealm structure
 *            sUsersPerClient - users per client description
 */

void
ServerRealm_set_sUsersPerClient(ServerRealm* sr, char* sUsersPerClient)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->sUsersPerClient), sUsersPerClient);
}

/*
 * Function name: ServerRealm_set_sClientMode
 * Description: Set client mode description.
 * Arguments: sr - pointer to ServerRealm structure
 *            sClientMode - client mode description
 */

void
ServerRealm_set_sClientMode(ServerRealm* sr, char* sClientMode)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->sClientMode), sClientMode);
}

/*
 * Function name: ServerRealm_set_sTimeout
 * Description: Set timeout value description.
 * Arguments: sr - pointer to ServerRealm structure
 *            sTimeout - timeout value description
 */

void
ServerRealm_set_sTimeout(ServerRealm* sr, char* sTimeout)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->sTimeout), sTimeout);
}

/*
 * Function name: ServerRealm_set_sMaxIdle
 * Description: Sets max idle value description.
 * Arguments: sr - pointer to ServerRealm structure
 *            sMaxIdle - max idle value description
 */

void
ServerRealm_set_sMaxIdle(ServerRealm* sr, char* sMaxIdle)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->sMaxIdle), sMaxIdle);
}

/*
 * Function name: ServerRealm_set_realmName
 * Description: Set realm's name.
 * Arguments: sr - pointer to ServerRealm structure
 *            realmName - realm's name
 */

void
ServerRealm_set_realmName(ServerRealm* sr, char* realmName)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  string_cp(&(sr->realmName), realmName);
}

/*
 * Function name: ServerRealm_set_password
 * Description: Set realm's password.
 * Arguments: sr - pointer to ServerRealm structure
 *            password - realm's password
 */

void
ServerRealm_set_password(ServerRealm* sr, unsigned char* password)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  memcpy(sr->password, password, 4);
}

/*
 * Function name: ServerRealm_set_connectedUsers
 * Description: Set number of connected users.
 * Arguments: sr - pointer to ServerRealm structure
 *            connectedUsers - number of connected users
 */

void
ServerRealm_set_connectedUsers(ServerRealm* sr, int connectedUsers)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->connectedUsers = connectedUsers;
}

/*
 * Function name: ServerRealm_set_usersLimit
 * Description: Set limit of connected users.
 * Arguments: sr - pointer to ServerRealm structure
 *            usersLimit - limit of connected users
 */

void
ServerRealm_set_usersLimit(ServerRealm* sr, int usersLimit)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->usersLimit = usersLimit;
}

/*
 * Function name: ServerRealm_set_connectedClients
 * Description: Set number of connected clients.
 * Arguments: sr - pointer to ServerRealm structure
 *            connectedClients - number of connected clients
 */

void
ServerRealm_set_connectedClients(ServerRealm* sr, int connectedClients)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->connectedClients = connectedClients;
}

/*
 * Function name: ServerRealm_set_clientsLimit
 * Description: Set limit of connected clients.
 * Arguments: sr - pointer to ServerRealm structure
 *            clientsLimit - limit of connected clients
 */

void
ServerRealm_set_clientsLimit(ServerRealm* sr, int clientsLimit)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->clientsLimit = clientsLimit;
}

/*
 * Function name: ServerRealm_set_connectedRaClients
 * Description: Set number of connected raClients.
 * Arguments: sr - pointer to ServerRealm structure
 *            connectedRaClients - number of connected raClients
 */

void
ServerRealm_set_connectedRaClients(ServerRealm* sr, int connectedRaClients)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->connectedRaClients = connectedRaClients;
}

/*
 * Function name: ServerRealm_set_raClientsLimit
 * Description: Set limit of connected raClients.
 * Arguments: sr - pointer to ServerRealm structure
 *            raClientsLimit - limit of connected raClients
 */

void
ServerRealm_set_raClientsLimit(ServerRealm* sr, int raClientsLimit)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->raClientsLimit = raClientsLimit;
}

/*
 * Function name: ServerRealm_set_usersPerClient
 * Description: Set users per client limit.
 * Arguments: sr - pointer to ServerRealm structure
 *            usersPerClient - users per client limit
 */

void
ServerRealm_set_usersPerClient(ServerRealm* sr, int usersPerClient)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->usersPerClient = usersPerClient;
}

/*
 * Function name: ServerRealm_set_timeout
 * Description: Set timeout value.
 * Arguments: sr - pointer to ServerRealm structure
 *            timeout - timeout value
 */

void
ServerRealm_set_timeout(ServerRealm* sr, int timeout)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->timeout = timeout;
}

/*
 * Function name: ServerRealm_set_maxIdle
 * Description: Sets mas idle value.
 * Arguments: sr - pointer to ServerRealm structure
 *            maxIdle - max idle value
 */

void
ServerRealm_set_maxIdle(ServerRealm* sr, int maxIdle)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->maxIdle = maxIdle;
}

/*
 * Function name: ServerRealm_set_clientMode
 * Description: Set client mode.
 * Arguments: sr - pointer to ServerRealm structure
 *            clientMode - client mode
 */

void
ServerRealm_set_clientMode(ServerRealm* sr, int clientMode)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->clientMode = clientMode;
}

/*
 * Function name: ServerRealm_set_userClientPairs
 * Description: Set user-client pairs amount.
 * Arguments: sr - pointer to ServerRealm structure
 *            userClientPairs - user-client pairs amount
 */

void
ServerRealm_set_userClientPairs(ServerRealm* sr, int userClientPairs)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->userClientPairs = userClientPairs;
}

/*
 * Function name: ServerRealm_set_clientsCounter
 * Description: Set clients counter state.
 * Arguments: sr - pointer to ServerRealm structure
 *            clientsCounter - clients counter state
 */

void
ServerRealm_set_clientsCounter(ServerRealm* sr, int clientsCounter)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->clientsCounter = clientsCounter;
}

/*
 * Function name: ServerRealm_set_usersCounter
 * Description: Set users counter state.
 * Arguments: sr - pointer to ServerRealm structure
 *            usersCounter - users counter state
 */

void
ServerRealm_set_usersCounter(ServerRealm* sr, int usersCounter)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->usersCounter = usersCounter;
}

/*
 * Function name: ServerRealm_set_realmType
 * Description: Set type of the realm.
 * Arguments: sr - pointer to ServerRealm structure
 *            realmType - type of the realm
 */

void
ServerRealm_set_realmType(ServerRealm* sr, char realmType)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->realmType = realmType;
}

/*
 * Function name: ServerRealm_set_tunnelType
 * Description: Set type of the tunnel.
 * Arguments: sr - pointer to ServerRealm structure
 *            tunnelType - type of the tunnel
 */

void
ServerRealm_set_tunnelType(ServerRealm* sr, char tunnelType)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->tunnelType = tunnelType;
}

/*
 * Function name: ServerRealm_set_dnsLookupsOn
 * Description: Set dns lookups functionality on/off.
 * Arguments: sr - pointer to ServerRealm structure
 *            dnsLookupsOn - dns lookups functionality on/off
 */

void
ServerRealm_set_dnsLookupsOn(ServerRealm* sr, char dnsLookupsOn)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->dnsLookupsOn = dnsLookupsOn;
}

/*
 * Function name: ServerRealm_set_basePortOn
 * Description: Set base port functionality on/off.
 * Arguments: sr - pointer to ServerRealm structure
 *            basePortOn - base port functionality on/off
 */

void
ServerRealm_set_basePortOn(ServerRealm* sr, char basePortOn)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->basePortOn = basePortOn;
}

/*
 * Function name: ServerRealm_set_auditOn
 * Description: Set audit functionality on/off.
 * Arguments: sr - pointer to ServerRealm structure
 *            auditOn - audit functionality on/off
 */

void
ServerRealm_set_auditOn(ServerRealm* sr, char auditOn)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->auditOn = auditOn;
}

/*
 * Function name: ServerRealm_set_addressLength
 * Description: Set client's address length.
 * Arguments: sr - pointer to ServerRealm structure
 *            addressLength - client's address length
 */

void
ServerRealm_set_addressLength(ServerRealm* sr, socklen_t addressLength)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  sr->addressLength = addressLength;
}

/*
 * Function name: ServerRealm_set_clientAddress
 * Description: Set client's network address.
 * Arguments: sr - pointer to ServerRealm structure
 *            clientAddress - client's network address
 */

void
ServerRealm_set_clientAddress(ServerRealm* sr, struct sockaddr* clientAddress)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  if (sr->clientAddress) {
    free(sr->clientAddress);
    sr->clientAddress = NULL;
  }
  sr->clientAddress = clientAddress;
}

/*
 * Function name: ServerRealm_set_usersTable
 * Description: Set table of users.
 * Arguments: sr - pointer to ServerRealm structure
 *            usersTable - table of users
 */

void
ServerRealm_set_usersTable(ServerRealm* sr, ConnectUser** usersTable)
{
  int i;
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  if (sr->usersTable) {
    for (i = 0; i < sr->usersLimit; ++i) {
      if (sr->usersTable[i]) {
        ConnectUser_free(&(sr->usersTable[i]));
      }
    }
    free(sr->usersTable);
    sr->usersTable = NULL;
  }
  sr->usersTable = usersTable;
}

/*
 * Function name: ServerRealm_set_clientsTable
 * Description: Set table of clients.
 * Arguments: sr - pointer to ServerRealm structure
 *            clientsTable - table of clients
 */

void
ServerRealm_set_clientsTable(ServerRealm* sr, ConnectClient** clientsTable)
{
  int i;
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  if (sr->clientsTable) {
    for (i = 0; i < sr->clientsLimit; ++i) {
      if (sr->clientsTable[i]) {
        ConnectClient_free(&(sr->clientsTable[i]));
      }
    }
    free(sr->clientsTable);
    sr->clientsTable = NULL;
  }
  sr->clientsTable = clientsTable;
}

/*
 * Function name: ServerRealm_set_raClientsTable
 * Description: Set table of raClients.
 * Arguments: sr - pointer to ServerRealm structure
 *            raClientsTable - table of raClients
 */

void
ServerRealm_set_raClientsTable(ServerRealm* sr, ConnectClient** raClientsTable)
{
  int i;
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  if (sr->raClientsTable) {
    for (i = 0; i < sr->raClientsLimit; ++i) {
      if (sr->raClientsTable[i]) {
        ConnectClient_free(&(sr->raClientsTable[i]));
      }
    }
    free(sr->raClientsTable);
    sr->raClientsTable = NULL;
  }
  sr->raClientsTable = raClientsTable;
}

/*
 * Function name: ServerRealm_set_usersClientsTable
 * Description: Set table of user-client pairs.
 * Arguments: sr - pointer to ServerRealm structure
 *            usersClientsTable - table of user-client pairs
 */

void
ServerRealm_set_usersClientsTable(ServerRealm* sr, UsrCli** usersClientsTable)
{
  int i;
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  if (sr->usersClientsTable) {
    for (i = 0; i < sr->userClientPairs; ++i) {
      if (sr->usersClientsTable[i]) {
        UsrCli_free(&(sr->usersClientsTable[i]));
      }
    }
    free(sr->usersClientsTable);
    sr->usersClientsTable = NULL;
  }
  sr->usersClientsTable = usersClientsTable;
}

/*
 * Function name: ServerRealm_get_hostName
 * Description: Get realm's host name.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Realm's host name.
 */

char*
ServerRealm_get_hostName(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->hostName;
}

/*
 * Function name: ServerRealm_get_sUsersLimit
 * Description: Get users limit description.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Users limit description.
 */

char*
ServerRealm_get_sUsersLimit(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->sUsersLimit;
}

/*
 * Function name: ServerRealm_get_sClientsLimit
 * Description: Get clients limit description.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Clients limit description.
 */

char*
ServerRealm_get_sClientsLimit(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->sClientsLimit;
}

/*
 * Function name: ServerRealm_get_sRaClientsLimit
 * Description: Get raClients limit description.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: RaClients limit description.
 */

char*
ServerRealm_get_sRaClientsLimit(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->sRaClientsLimit;
}

/*
 * Function name: ServerRealm_get_sUsersPerClient
 * Description: Get users per client description.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Users per client description.
 */

char*
ServerRealm_get_sUsersPerClient(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->sUsersPerClient;
}

/*
 * Function name: ServerRealm_get_sClientMode
 * Description: Get client mode description.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Client mode description.
 */

char*
ServerRealm_get_sClientMode(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->sClientMode;
}

/*
 * Function name: ServerRealm_get_sTimeout
 * Description: Get timeout value description.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Timeout value description.
 */

char*
ServerRealm_get_sTimeout(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->sTimeout;
}

/*
 * Function name: ServerRealm_get_sMaxIdle
 * Description: Gets max idle value description.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Max idle value description.
 */

char*
ServerRealm_get_sMaxIdle(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->sMaxIdle;
}

/*
 * Function name: ServerRealm_get_realmName
 * Description: Get realm's name.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Realm's name.
 */

char*
ServerRealm_get_realmName(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->realmName;
}

/*
 * Function name: ServerRealm_get_password
 * Description: Get realm's password.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Realm's password.
 */

unsigned char*
ServerRealm_get_password(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->password;
}

/*
 * Function name: ServerRealm_get_connectedUsers
 * Description: Get number of connected users.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Number of connected users.
 */

int
ServerRealm_get_connectedUsers(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->connectedUsers;
}

/*
 * Function name: ServerRealm_get_usersLimit
 * Description: Get limit of connected users.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Limit of connected users.
 */

int
ServerRealm_get_usersLimit(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->usersLimit;
}

/*
 * Function name: ServerRealm_get_connectedClients
 * Description: Get number of connected clients.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Number of connected clients.
 */

int
ServerRealm_get_connectedClients(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->connectedClients;
}

/*
 * Function name: ServerRealm_get_clientsLimit
 * Description: Get limit of connected clients.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Limit of connected clients.
 */

int
ServerRealm_get_clientsLimit(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->clientsLimit;
}

/*
 * Function name: ServerRealm_get_connectedRaClients
 * Description: Get number of connected raClients.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Number of connected raClients.
 */

int
ServerRealm_get_connectedRaClients(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->connectedRaClients;
}

/*
 * Function name: ServerRealm_get_raClientsLimit
 * Description: Get limit of connected raClients.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Limit of connected raClients.
 */

int
ServerRealm_get_raClientsLimit(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->raClientsLimit;
}

/*
 * Function name: ServerRealm_get_usersPerClient
 * Description: Get users per client limit.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Users per client limit.
 */

int
ServerRealm_get_usersPerClient(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->usersPerClient;
}

/*
 * Function name: ServerRealm_get_timeout
 * Description: Get timeout value.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Timeout value.
 */

int
ServerRealm_get_timeout(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->timeout;
}

/*
 * Function name: ServerRealm_get_maxIdle
 * Description: Gets max idle value.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Max idle value.
 */

int
ServerRealm_get_maxIdle(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->maxIdle;
}

/*
 * Function name: ServerRealm_get_clientMode
 * Description: Get client mode.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Client mode.
 */

int
ServerRealm_get_clientMode(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->clientMode;
}

/*
 * Function name: ServerRealm_get_userClientPairs
 * Description: Get user-client pairs amount.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: User-client pairs amount.
 */

int
ServerRealm_get_userClientPairs(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->userClientPairs;
}

/*
 * Function name: ServerRealm_get_clientsCounter
 * Description: Get clients counter state.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Clients counter state.
 */

int
ServerRealm_get_clientsCounter(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->clientsCounter;
}

/*
 * Function name: ServerRealm_get_usersCounter
 * Description: Get users counter state.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Users counter state.
 */

int
ServerRealm_get_usersCounter(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return -1;
  }
  return sr->usersCounter;
}

/*
 * Function name: ServerRealm_get_realmType
 * Description: Get type of the realm.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Type of the realm.
 */

char
ServerRealm_get_realmType(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->realmType;
}

/*
 * Function name: ServerRealm_get_tunnelType
 * Description: Get type of the tunnel.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Type of the tunnel.
 */

char
ServerRealm_get_tunnelType(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->tunnelType;
}

/*
 * Function name: ServerRealm_get_dnsLookupsOn
 * Description: Get dns lookups functionality on/off.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Dns lookups functionality on/off.
 */

char
ServerRealm_get_dnsLookupsOn(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->dnsLookupsOn;
}

/*
 * Function name: ServerRealm_get_basePortOn
 * Description: Get base port functionality on/off.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Base port functionality on/off.
 */

char
ServerRealm_get_basePortOn(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->basePortOn;
}

/*
 * Function name: ServerRealm_get_auditOn
 * Description: Get audit functionality on/off.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Audit functionality on/off.
 */

char
ServerRealm_get_auditOn(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->auditOn;
}

/*
 * Function name: ServerRealm_get_addressLength
 * Description: Get client's address length.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Client's address length.
 */

socklen_t
ServerRealm_get_addressLength(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return 0;
  }
  return sr->addressLength;
}

/*
 * Function name: ServerRealm_get_clientAddress
 * Description: Get client's network address.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Client's network address.
 */

struct sockaddr*
ServerRealm_get_clientAddress(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->clientAddress;
}

/*
 * Function name: ServerRealm_get_usersTable
 * Description: Get table of users.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Table of users.
 */

ConnectUser**
ServerRealm_get_usersTable(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->usersTable;
}

/*
 * Function name: ServerRealm_get_clientsTable
 * Description: Get table of clients.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Table of clients.
 */

ConnectClient**
ServerRealm_get_clientsTable(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->clientsTable;
}

/*
 * Function name: ServerRealm_get_raClientsTable
 * Description: Get table of raClients.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Table of raClients.
 */

ConnectClient**
ServerRealm_get_raClientsTable(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->raClientsTable;
}

/*
 * Function name: ServerRealm_get_usersClientsTable
 * Description: Get table of user-client pairs.
 * Arguments: sr - pointer to ServerRealm structure
 * Returns: Table of user-client pairs.
 */

UsrCli**
ServerRealm_get_usersClientsTable(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return NULL;
  }
  return sr->usersClientsTable;
}

/*
 * Function name: ServerRealm_increase_connectedUsers
 * Description: Increase number of connected users.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_increase_connectedUsers(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_connectedUsers(sr, ServerRealm_get_connectedUsers(sr) + 1);
}

/*
 * Function name: ServerRealm_decrease_connectedUsers
 * Description: Decrease number of connected users.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_decrease_connectedUsers(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_connectedUsers(sr, ServerRealm_get_connectedUsers(sr) - 1);
}

/*
 * Function name: ServerRealm_increase_connectedClients
 * Description: Increase number of connected clients.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_increase_connectedClients(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_connectedClients(sr, ServerRealm_get_connectedClients(sr) + 1);
}

/*
 * Function name: ServerRealm_decrease_connectedClients
 * Description: Decrease number of connected clients.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_decrease_connectedClients(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_connectedClients(sr, ServerRealm_get_connectedClients(sr) - 1);
}

/*
 * Function name: ServerRealm_increase_connectedRaClients
 * Description: Increase number of connected raClients.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_increase_connectedRaClients(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_connectedRaClients(sr, ServerRealm_get_connectedRaClients(sr) + 1);
}

/*
 * Function name: ServerRealm_decrease_connectedRaClients
 * Description: Decrease number of connected raClients.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_decrease_connectedRaClients(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_connectedRaClients(sr, ServerRealm_get_connectedRaClients(sr) - 1);
}

/*
 * Function name: ServerRealm_increase_usersCounter
 * Description: Increase users counter state.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_increase_usersCounter(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_usersCounter(sr, ServerRealm_get_usersCounter(sr) + 1);
}

/*
 * Function name: ServerRealm_increase_clientsCounter
 * Description: Increase clients counter state.
 * Arguments: sr - pointer to ServerRealm structure
 */

void
ServerRealm_increase_clientsCounter(ServerRealm* sr)
{
  assert(sr != NULL);
  if (sr == NULL) {
    return;
  }
  ServerRealm_set_clientsCounter(sr, ServerRealm_get_clientsCounter(sr) + 1);
}

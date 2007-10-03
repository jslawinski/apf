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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "string_functions.h"
#include "client_realm_struct.h"
#include "client_shutdown.h"
#include "logging.h"

/*
 * Function name: ClientRealm_new
 * Description: Create and initialize new ClientRealm structure.
 * Returns: Pointer to newly created ClientRealm structure.
 */

ClientRealm*
ClientRealm_new()
{
  ClientRealm* tmp = calloc(1, sizeof(ClientRealm));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  tmp->password[0] = 1;
  tmp->password[1] = 2;
  tmp->password[2] = 3;
  tmp->password[3] = 4;
  tmp->masterSslFd = SslFd_new();
  assert(tmp->masterSslFd != NULL);
  if (tmp->masterSslFd == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
  tmp->arOptions = ArOptions_new();
  assert(tmp->arOptions != NULL);
  if (tmp->arOptions == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
  tmp->httpProxyOptions = HttpProxyOptions_new();
  assert(tmp->httpProxyOptions != NULL);
  if (tmp->httpProxyOptions == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
#ifdef HAVE_LIBDL
  tmp->userModule = Module_new();
  assert(tmp->userModule != NULL);
  if (tmp->userModule == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
  tmp->serviceModule = Module_new();
  assert(tmp->serviceModule != NULL);
  if (tmp->serviceModule == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
#endif
  return tmp;
}

/*
 * Function name: ClientRealm_free
 * Description: Free the memory allocated for ClientRealm structure.
 * Arguments: cr - pointer to pointer to ClientRealm structure
 */

void
ClientRealm_free(ClientRealm** cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  assert((*cr) != NULL);
  if ((*cr) == NULL) {
    return;
  }
  ClientRealm_set_serverName((*cr), NULL);
  ClientRealm_set_managePort((*cr), NULL);
  ClientRealm_set_hostName((*cr), NULL);
  ClientRealm_set_realmName((*cr), NULL);
  ClientRealm_set_sKeepAliveTimeout((*cr), NULL);
  ClientRealm_set_realmId((*cr), NULL);
  ClientRealm_set_localName((*cr), NULL);
  ClientRealm_set_localPort((*cr), NULL);
  ClientRealm_set_localDestinationName((*cr), NULL);
  ClientRealm_set_clientAddress((*cr), NULL);
  ClientRealm_set_masterSslFd((*cr), NULL);
  ClientRealm_set_httpProxyOptions((*cr), NULL);
  ClientRealm_set_arOptions((*cr), NULL);
  ClientRealm_set_destinationPorts((*cr), NULL);
  ClientRealm_set_usersTable((*cr), NULL);
#ifdef HAVE_LIBDL
  ClientRealm_set_userModule((*cr), NULL);
  ClientRealm_set_serviceModule((*cr), NULL);
#endif
  free((*cr));
  (*cr) = NULL;
}

/*
 * Function name: ClientRealm_set_serverName
 * Description: Set realm's server name.
 * Arguments: cr - pointer to ClientRealm structure
 *            serverName - realm's host name
 */

void
ClientRealm_set_serverName(ClientRealm* cr, char* serverName)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->serverName), serverName);
}

/*
 * Function name: ClientRealm_set_managePort
 * Description: Set realm's manage port description.
 * Arguments: cr - pointer to ClientRealm structure
 *            managePort - realm's manage port description
 */

void
ClientRealm_set_managePort(ClientRealm* cr, char* managePort)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->managePort), managePort);
}

/*
 * Function name: ClientRealm_set_hostName
 * Description: Set realm's host name.
 * Arguments: cr - pointer to ClientRealm structure
 *            hostName - realm's host name
 */

void
ClientRealm_set_hostName(ClientRealm* cr, char* hostName)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->hostName), hostName);
}

/*
 * Function name: ClientRealm_set_destinationPorts
 * Description: Set realm's destination ports list.
 * Arguments: cr - pointer to ClientRealm structure
 *            destinationPorts - realm's destination ports list
 */

void
ClientRealm_set_destinationPorts(ClientRealm* cr, PortList* destinationPorts)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->destinationPorts) {
    PortList_free(&(cr->destinationPorts));
  }
  cr->destinationPorts = destinationPorts;
}

/*
 * Function name: ClientRealm_set_sKeepAliveTimeout
 * Description: Set keep-alive timeout value description.
 * Arguments: cr - pointer to ClientRealm structure
 *            sKeepAliveTimeout - keep-alive timeout value description
 */

void
ClientRealm_set_sKeepAliveTimeout(ClientRealm* cr, char* sKeepAliveTimeout)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->sKeepAliveTimeout), sKeepAliveTimeout);
}

/*
 * Function name: ClientRealm_set_realmName
 * Description: Set realm's name.
 * Arguments: cr - pointer to ClientRealm structure
 *            realmName - realm's name
 */

void
ClientRealm_set_realmName(ClientRealm* cr, char* realmName)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->realmName), realmName);
}

/*
 * Function name: ClientRealm_set_realmId
 * Description: Set realm's id.
 * Arguments: cr - pointer to ClientRealm structure
 *            realmId - realm's id
 */

void
ClientRealm_set_realmId(ClientRealm* cr, char* realmId)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->realmId), realmId);
}

/*
 * Function name: ClientRealm_set_localName
 * Description: Set realm's local name.
 * Arguments: cr - pointer to ClientRealm structure
 *            localName - realm's local name
 */

void
ClientRealm_set_localName(ClientRealm* cr, char* localName)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->localName), localName);
}

/*
 * Function name: ClientRealm_set_localPort
 * Description: Set realm's local port description.
 * Arguments: cr - pointer to ClientRealm structure
 *            localPort - realm's local port description
 */

void
ClientRealm_set_localPort(ClientRealm* cr, char* localPort)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->localPort), localPort);
}

/*
 * Function name: ClientRealm_set_localDestinationName
 * Description: Set realm's local destination name.
 * Arguments: cr - pointer to ClientRealm structure
 *            localDestinationName - realm's local destination name
 */

void
ClientRealm_set_localDestinationName(ClientRealm* cr, char* localDestinationName)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->localDestinationName), localDestinationName);
}

/*
 * Function name: ClientRealm_set_password
 * Description: Set realm's password.
 * Arguments: cr - pointer to ClientRealm structure
 *            password - realm's password
 */

void
ClientRealm_set_password(ClientRealm* cr, unsigned char* password)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  memcpy(cr->password, password, 4);
}

/*
 * Function name: ClientRealm_set_connectedUsers
 * Description: Set number of connected users.
 * Arguments: cr - pointer to ClientRealm structure
 *            connectedUsers - number of connected users
 */

void
ClientRealm_set_connectedUsers(ClientRealm* cr, int connectedUsers)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->connectedUsers = connectedUsers;
}

/*
 * Function name: ClientRealm_set_usersLimit
 * Description: Set limit of connected users.
 * Arguments: cr - pointer to ClientRealm structure
 *            usersLimit - limit of connected users
 */

void
ClientRealm_set_usersLimit(ClientRealm* cr, int usersLimit)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->usersLimit = usersLimit;
}

/*
 * Function name: ClientRealm_set_keepAliveTimeout
 * Description: Set keep-alive timeout value.
 * Arguments: cr - pointer to ClientRealm structure
 *            keepAliveTimeout - keep-alive timeout value
 */

void
ClientRealm_set_keepAliveTimeout(ClientRealm* cr, int keepAliveTimeout)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->keepAliveTimeout = keepAliveTimeout;
}

/*
 * Function name: ClientRealm_set_clientMode
 * Description: Set client mode.
 * Arguments: cr - pointer to ClientRealm structure
 *            clientMode - client mode
 */

void
ClientRealm_set_clientMode(ClientRealm* cr, int clientMode)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->clientMode = clientMode;
}

/*
 * Function name: ClientRealm_set_ipFamily
 * Description: Set IP family.
 * Arguments: cr - pointer to ClientRealm structure
 *            ipFamily - IP family
 */

void
ClientRealm_set_ipFamily(ClientRealm* cr, char ipFamily)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->ipFamily = ipFamily;
}

/*
 * Function name: ClientRealm_set_realmType
 * Description: Set type of the realm.
 * Arguments: cr - pointer to ClientRealm structure
 *            realmType - type of the realm
 */

void
ClientRealm_set_realmType(ClientRealm* cr, char realmType)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->realmType = realmType;
}

/*
 * Function name: ClientRealm_set_tunnelType
 * Description: Set type of the tunnel.
 * Arguments: cr - pointer to ClientRealm structure
 *            tunnelType - type of the tunnel
 */

void
ClientRealm_set_tunnelType(ClientRealm* cr, char tunnelType)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->tunnelType = tunnelType;
}

/*
 * Function name: ClientRealm_set_keepAlive
 * Description: Set keep-alive timeval struct.
 * Arguments: cr - pointer to ClientRealm structure
 *            keepAlive - keep-alive timeval struct
 */

void
ClientRealm_set_keepAlive(ClientRealm* cr, struct timeval keepAlive)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->keepAlive = keepAlive;
}

/*
 * Function name: ClientRealm_set_addressLength
 * Description: Set client's address length.
 * Arguments: cr - pointer to ClientRealm structure
 *            addressLength - client's address length
 */

void
ClientRealm_set_addressLength(ClientRealm* cr, socklen_t addressLength)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  cr->addressLength = addressLength;
}

/*
 * Function name: ClientRealm_set_clientAddress
 * Description: Set client's network address.
 * Arguments: cr - pointer to ClientRealm structure
 *            clientAddress - client's network address
 */

void
ClientRealm_set_clientAddress(ClientRealm* cr, struct sockaddr* clientAddress)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->clientAddress) {
    free(cr->clientAddress);
    cr->clientAddress = NULL;
  }
  cr->clientAddress = clientAddress;
}

/*
 * Function name: ClientRealm_set_masterSslFd
 * Description: Set client realm's master sslfd.
 * Arguments: cr - pointer to ClientRealm structure
 *            masterSslFd - client realm's master sslfd
 */

void
ClientRealm_set_masterSslFd(ClientRealm* cr, SslFd* masterSslFd)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->masterSslFd) {
    SslFd_free(&(cr->masterSslFd));
  }
  cr->masterSslFd = masterSslFd;
}

/*
 * Function name: ClientRealm_set_httpProxyOptions
 * Description: Set client realm's http proxy options.
 * Arguments: cr - pointer to ClientRealm structure
 *            httpProxyOptions - client realm's http proxy options
 */

void
ClientRealm_set_httpProxyOptions(ClientRealm* cr, HttpProxyOptions* httpProxyOptions)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->httpProxyOptions) {
    HttpProxyOptions_free(&(cr->httpProxyOptions));
  }
  cr->httpProxyOptions = httpProxyOptions;
}

/*
 * Function name: ClientRealm_set_arOptions
 * Description: Set client realm's auto-reconnect options.
 * Arguments: cr - pointer to ClientRealm structure
 *            arOptions - client realm's auto-reconnect options
 */

void
ClientRealm_set_arOptions(ClientRealm* cr, ArOptions* arOptions)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->arOptions) {
    ArOptions_free(&(cr->arOptions));
  }
  cr->arOptions = arOptions;
}

/*
 * Function name: ClientRealm_set_usersTable
 * Description: Set table of users.
 * Arguments: cr - pointer to ClientRealm structure
 *            usersTable - table of users
 */

void
ClientRealm_set_usersTable(ClientRealm* cr, ConnectUser** usersTable)
{
  int i;
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->usersTable) {
    for (i = 0; i < cr->usersLimit; ++i) {
      if (cr->usersTable[i]) {
        ConnectUser_free(&(cr->usersTable[i]));
      }
    }
    free(cr->usersTable);
    cr->usersTable = NULL;
  }
  cr->usersTable = usersTable;
}

#ifdef HAVE_LIBDL
/*
 * Function name: ClientRealm_set_userModule
 * Description: Set a module for user's packets filtering.
 * Arguments: cr - pointer to ClientRealm structure
 *            userModule - module for user's packets filtering
 */

void
ClientRealm_set_userModule(ClientRealm* cr, Module* userModule)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->userModule) {
    Module_free(&(cr->userModule));
  }
  cr->userModule = userModule;
}

/*
 * Function name: ClientRealm_set_serviceModule
 * Description: Set a module for service's packets filtering.
 * Arguments: cr - pointer to ClientRealm structure
 *            serviceModule - module for service's packets filtering
 */

void
ClientRealm_set_serviceModule(ClientRealm* cr, Module* serviceModule)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if (cr->serviceModule) {
    Module_free(&(cr->serviceModule));
  }
  cr->serviceModule = serviceModule;
}
#endif

/*
 * Function name: ClientRealm_get_serverName
 * Description: Get realm's server name.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's server name.
 */

char*
ClientRealm_get_serverName(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->serverName;
}

/*
 * Function name: ClientRealm_get_managePort
 * Description: Get realm's manage port description.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's manage port description.
 */

char*
ClientRealm_get_managePort(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->managePort;
}

/*
 * Function name: ClientRealm_get_hostName
 * Description: Get realm's host name.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's host name.
 */

char*
ClientRealm_get_hostName(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->hostName;
}

/*
 * Function name: ClientRealm_get_destinationPorts
 * Description: Get realm's destination ports list.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's destination ports list.
 */

PortList*
ClientRealm_get_destinationPorts(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->destinationPorts;
}

/*
 * Function name: ClientRealm_get_sKeepAliveTimeout
 * Description: Get keep-alive timeout value description.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Keep-alive timeout value description.
 */

char*
ClientRealm_get_sKeepAliveTimeout(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->sKeepAliveTimeout;
}

/*
 * Function name: ClientRealm_get_realmName
 * Description: Get realm's name.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's name.
 */

char*
ClientRealm_get_realmName(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->realmName;
}

/*
 * Function name: ClientRealm_get_realmId
 * Description: Get realm's id.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's id.
 */

char*
ClientRealm_get_realmId(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->realmId;
}


/*
 * Function name: ClientRealm_get_localName
 * Description: Get realm's local name.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's local name.
 */

char*
ClientRealm_get_localName(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->localName;
}


/*
 * Function name: ClientRealm_get_localPort
 * Description: Get realm's local port description.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's local port description.
 */

char*
ClientRealm_get_localPort(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->localPort;
}


/*
 * Function name: ClientRealm_get_localDestinationName
 * Description: Get realm's local destination name.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's local destination name.
 */

char*
ClientRealm_get_localDestinationName(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->localDestinationName;
}

/*
 * Function name: ClientRealm_get_password
 * Description: Get realm's password.
 * Arguments: sr - pointer to ClientRealm structure
 * Returns: Realm's password.
 */

unsigned char*
ClientRealm_get_password(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->password;
}

/*
 * Function name: ClientRealm_get_connectedUsers
 * Description: Get number of connected users.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Number of connected users.
 */

int
ClientRealm_get_connectedUsers(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return -1;
  }
  return cr->connectedUsers;
}

/*
 * Function name: ClientRealm_get_usersLimit
 * Description: Get limit of connected users.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Limit of connected users.
 */

int
ClientRealm_get_usersLimit(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return -1;
  }
  return cr->usersLimit;
}

/*
 * Function name: ClientRealm_get_keepAliveTimeout
 * Description: Get keep-alive timeout value.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Keep-alive timeout value.
 */

int
ClientRealm_get_keepAliveTimeout(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return 0;
  }
  return cr->keepAliveTimeout;
}

/*
 * Function name: ClientRealm_get_clientMode
 * Description: Get client mode.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Client mode.
 */

int
ClientRealm_get_clientMode(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return 0;
  }
  return cr->clientMode;
}

/*
 * Function name: ClientRealm_get_ipFamily
 * Description: Get IP family.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: IP family.
 */

char
ClientRealm_get_ipFamily(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return 0;
  }
  return cr->ipFamily;
}

/*
 * Function name: ClientRealm_get_realmType
 * Description: Get type of the realm.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Type of the realm.
 */

char
ClientRealm_get_realmType(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return 0;
  }
  return cr->realmType;
}

/*
 * Function name: ClientRealm_get_tunnelType
 * Description: Get type of the tunnel.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Type of the tunnel.
 */

char
ClientRealm_get_tunnelType(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return 0;
  }
  return cr->tunnelType;
}

/*
 * Function name: ClientRealm_get_keepAlive
 * Description: Get keep-alive timeval struct.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Keep-alive timeval struct.
 */

struct timeval
ClientRealm_get_keepAlive(ClientRealm* cr)
{
  struct timeval tmp = {0, 0};
  assert(cr != NULL);
  if (cr == NULL) {
    return tmp;
  }
  return cr->keepAlive;
}

/*
 * Function name: ClientRealm_get_addressLength
 * Description: Get client's address length.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Client's address length.
 */

socklen_t
ClientRealm_get_addressLength(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return 0;
  }
  return cr->addressLength;
}

/*
 * Function name: ClientRealm_get_clientAddress
 * Description: Get client's network address.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Client's network address.
 */

struct sockaddr*
ClientRealm_get_clientAddress(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->clientAddress;
}

/*
 * Function name: ClientRealm_get_masterSslFd
 * Description: Get client realm's master sslfd.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Client realm's master sslfd.
 */

SslFd*
ClientRealm_get_masterSslFd(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->masterSslFd;
}

/*
 * Function name: ClientRealm_get_httpProxyOptions
 * Description: Get client realm's http proxy options.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Client realm's http proxy options.
 */

HttpProxyOptions*
ClientRealm_get_httpProxyOptions(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->httpProxyOptions;
}

/*
 * Function name: ClientRealm_get_arOptions
 * Description: Get client realm's auto-reconnect options.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Client realm's auto-reconnect options.
 */

ArOptions*
ClientRealm_get_arOptions(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->arOptions;
}

/*
 * Function name: ClientRealm_get_usersTable
 * Description: Get table of users.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Table of users.
 */

ConnectUser**
ClientRealm_get_usersTable(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->usersTable;
}

#ifdef HAVE_LIBDL
/*
 * Function name: ClientRealm_get_userModule
 * Description: Get a module for user's packets filtering.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: A module for user's packets filtering.
 */

Module*
ClientRealm_get_userModule(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->userModule;
}

/*
 * Function name: ClientRealm_get_serviceModule
 * Description: Get a module for service's packets filtering.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: A module for service's packets filtering.
 */

Module*
ClientRealm_get_serviceModule(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return cr->serviceModule;
}
#endif

/*
 * Function name: ClientRealm_increase_connectedUsers
 * Description: Increase number of connected users.
 * Arguments: cr - pointer to ClientRealm structure
 */

void
ClientRealm_increase_connectedUsers(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  ClientRealm_set_connectedUsers(cr, ClientRealm_get_connectedUsers(cr) + 1);
}

/*
 * Function name: ClientRealm_decrease_connectedUsers
 * Description: Decrease number of connected users.
 * Arguments: cr - pointer to ClientRealm structure
 */

void
ClientRealm_decrease_connectedUsers(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  ClientRealm_set_connectedUsers(cr, ClientRealm_get_connectedUsers(cr) - 1);
}

/*
 * Function name: ClientRealm_closeUsersConnections
 * Description: Close all users' connections and free usersTable.
 * Arguments: cr - pointer to ClientRealm structure
 */

void
ClientRealm_closeUsersConnections(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  close_connections(ClientRealm_get_usersLimit(cr), &(cr->usersTable));
}

/*
 * Function name: ClientRealm_get_keepAlivePointer
 * Description: Get pointer to keep-alive structure.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Pointer to keep-alive structure.
 */

struct timeval*
ClientRealm_get_keepAlivePointer(ClientRealm* cr)
{
  assert(cr != NULL);
  if (cr == NULL) {
    return NULL;
  }
  return (&(cr->keepAlive));
}

/*
 * Function name: ClientRealm_send_realmId
 * Description: Sends the realm's id to the afserver.
 * Arguments: cr - pointer to ClientRealm structure
 *            buff - buffer used for message creation
 */

void
ClientRealm_send_realmId(ClientRealm* cr, unsigned char* buff)
{
  int n;
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  assert(buff != NULL);
  if (buff == NULL) {
    return;
  }
  if (ClientRealm_get_realmId(cr) != NULL) {
    buff[0] = AF_S_LOGIN;
    buff[1] = buff[2] = 0;
    n = strlen(ClientRealm_get_realmId(cr));
    memcpy(&buff[5], ClientRealm_get_realmId(cr), n);
    buff[3] = n >> 8; /* high bits of message length */
    buff[4] = n;    /* low bits of message length */
    SslFd_send_message(ClientRealm_get_realmType(cr),
        ClientRealm_get_masterSslFd(cr), buff, n+5);
    aflog(LOG_T_CLIENT, LOG_I_INFO,
        "ID SENT: %s", ClientRealm_get_realmId(cr));
  }
}

/*
 * Function name: ClientRealm_enable_multi
 * Description: Enables the MULTI mode on the afserver, if supported.
 * Arguments: cr - pointer to ClientRealm structure
 */

void
ClientRealm_enable_multi(ClientRealm* cr)
{
  unsigned char buff[5];
  assert(cr != NULL);
  if (cr == NULL) {
    return;
  }
  if ((TYPE_IS_SUPPORTED_MULTI(ClientRealm_get_realmType(cr))) &&
      (PortList_get_size(ClientRealm_get_destinationPorts(cr)) > 1)) {
    buff[0] = AF_S_ENABLE_MULTI;
    buff[1] = PortList_get_size(ClientRealm_get_destinationPorts(cr));
    buff[2] = buff[3] = buff[4] = 0;
    SslFd_send_message(ClientRealm_get_realmType(cr),
        ClientRealm_get_masterSslFd(cr), buff, 5);
    aflog(LOG_T_CLIENT, LOG_I_INFO,
        "ENABLED: MULTI (multiple tunnels managed by one afclient)");
  }
}

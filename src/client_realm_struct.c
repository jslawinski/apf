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

#include "string_functions.h"
#include "client_realm_struct.h"
#include "client_shutdown.h"

/*
 * Function name: ClientRealm_new
 * Description: Create and initialize new ClientRealm structure.
 * Returns: Pointer to newly created ClientRealm structure.
 */

ClientRealm*
ClientRealm_new()
{
  ClientRealm* tmp = calloc(1, sizeof(ClientRealm));
  if (tmp == NULL) {
    return NULL;
  }
  tmp->password[0] = 1;
  tmp->password[1] = 2;
  tmp->password[2] = 3;
  tmp->password[3] = 4;
  tmp->masterSslFd = SslFd_new();
  if (tmp->masterSslFd == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
  tmp->arOptions = ArOptions_new();
  if (tmp->arOptions == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
  tmp->httpProxyOptions = HttpProxyOptions_new();
  if (tmp->httpProxyOptions == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
#ifdef HAVE_LIBDL
  tmp->userModule = Module_new();
  if (tmp->userModule == NULL) {
    ClientRealm_free(&tmp);
    return NULL;
  }
  tmp->serviceModule = Module_new();
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
  int i;
  if (cr == NULL) {
    return;
  }
  if ((*cr) == NULL) {
    return;
  }
  if ((*cr)->serverName) {
    free((*cr)->serverName);
    (*cr)->serverName = NULL;
  }
  if ((*cr)->managePort) {
    free((*cr)->managePort);
    (*cr)->managePort = NULL;
  }
  if ((*cr)->hostName) {
    free((*cr)->hostName);
    (*cr)->hostName = NULL;
  }
  if ((*cr)->destinationPort) {
    free((*cr)->destinationPort);
    (*cr)->destinationPort = NULL;
  }
  if ((*cr)->sKeepAliveTimeout) {
    free((*cr)->sKeepAliveTimeout);
    (*cr)->sKeepAliveTimeout = NULL;
  }
  if ((*cr)->realmName) {
    free((*cr)->realmName);
    (*cr)->realmName = NULL;
  }
  if ((*cr)->clientAddress) {
    free((*cr)->clientAddress);
    (*cr)->clientAddress = NULL;
  }
  if ((*cr)->usersTable) {
    for (i = 0; i < (*cr)->usersLimit; ++i) {
      if ((*cr)->usersTable[i]) {
        ConnectUser_free(&((*cr)->usersTable[i]));
      }
    }
    free((*cr)->usersTable);
    (*cr)->usersTable = NULL;
  }
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
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->hostName), hostName);
}

/*
 * Function name: ClientRealm_set_destinationPort
 * Description: Set realm's destination port description.
 * Arguments: cr - pointer to ClientRealm structure
 *            destinationPort - realm's destination port description
 */

void
ClientRealm_set_destinationPort(ClientRealm* cr, char* destinationPort)
{
  if (cr == NULL) {
    return;
  }
  string_cp(&(cr->destinationPort), destinationPort);
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
  if (cr == NULL) {
    return NULL;
  }
  return cr->hostName;
}

/*
 * Function name: ClientRealm_get_destinationPort
 * Description: Get realm's destination port description.
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Realm's destination port description.
 */

char*
ClientRealm_get_destinationPort(ClientRealm* cr)
{
  if (cr == NULL) {
    return NULL;
  }
  return cr->destinationPort;
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
  if (cr == NULL) {
    return;
  }
  ClientRealm_set_connectedUsers(cr, ClientRealm_get_connectedUsers(cr) - 1);
}

/*
 * Function name: ClientRealm_closeUsersConnections
 * Description: Close all users' connections and free usersTable
 * Arguments: cr - pointer to ClientRealm structure
 */

void
ClientRealm_closeUsersConnections(ClientRealm* cr)
{
  if (cr == NULL) {
    return;
  }
  close_connections(ClientRealm_get_usersLimit(cr), &(cr->usersTable));
}

/*
 * Function name: ClientRealm_get_keepAlivePointer
 * Description: Get pointer to keep-alive structure
 * Arguments: cr - pointer to ClientRealm structure
 * Returns: Pointer to keep-alive structure
 */

struct timeval*
ClientRealm_get_keepAlivePointer(ClientRealm* cr)
{
  if (cr == NULL) {
    return NULL;
  }
  return (&(cr->keepAlive));
}

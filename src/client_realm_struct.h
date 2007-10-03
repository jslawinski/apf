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

#include "activefor.h"
#include "ssl_fd_struct.h"
#include "http_proxy_options_struct.h"
#include "ar_options_struct.h"
#include "module_struct.h"
#include "port_list_struct.h"

#ifndef _JS_CLIENT_REALM_STRUCT_H
#define _JS_CLIENT_REALM_STRUCT_H

#define CLIENTREALM_MODE_UNKNOWN -1
#define CLIENTREALM_MODE_TCP 0
#define CLIENTREALM_MODE_UDP 1
#define CLIENTREALM_MODE_REMOTE 2
#define CLIENTREALM_MODE_REVERSE 3

#define CLIENTREALM_TUNNELTYPE_UNKNOWN -1
#define CLIENTREALM_TUNNELTYPE_DIRECT 0
#define CLIENTREALM_TUNNELTYPE_HTTPPROXY 1
#define CLIENTREALM_TUNNELTYPE_HTTPSPROXY 2

typedef struct {
  char* serverName;
  char* managePort;
  char* hostName;
  char* realmName;
  char* sKeepAliveTimeout;
  char* realmId;
  char* localName;
  char* localPort;
  char* localDestinationName;
  unsigned char password[4];
  int connectedUsers;
  int usersLimit;
  int clientMode;
  int keepAliveTimeout;
  char ipFamily;
  char realmType;
  char tunnelType;
  struct timeval keepAlive;
  socklen_t addressLength;
  struct sockaddr* clientAddress;
  SslFd* masterSslFd;
  HttpProxyOptions* httpProxyOptions;
  ArOptions* arOptions;
  PortList* destinationPorts;
  ConnectUser** usersTable;
#ifdef HAVE_LIBDL
  Module* userModule;
  Module* serviceModule;
#endif
} ClientRealm;

/* 'constructor' */
ClientRealm* ClientRealm_new();
/* 'destructor' */
void ClientRealm_free(ClientRealm** cr);
/* setters */
void ClientRealm_set_serverName(ClientRealm* cr, char* serverName);
void ClientRealm_set_managePort(ClientRealm* cr, char* managePort);
void ClientRealm_set_hostName(ClientRealm* cr, char* hostName);
void ClientRealm_set_realmName(ClientRealm* cr, char* realmName);
void ClientRealm_set_sKeepAliveTimeout(ClientRealm* cr, char* sKeepAliveTimeout);
void ClientRealm_set_realmId(ClientRealm* cr, char* realmId);
void ClientRealm_set_localName(ClientRealm* cr, char* localName);
void ClientRealm_set_localPort(ClientRealm* cr, char* localPort);
void ClientRealm_set_localDestinationName(ClientRealm* cr, char* localDestinationName);
void ClientRealm_set_password(ClientRealm* cr, unsigned char* password);
void ClientRealm_set_connectedUsers(ClientRealm* cr, int connectedUsers);
void ClientRealm_set_usersLimit(ClientRealm* cr, int usersLimit);
void ClientRealm_set_keepAliveTimeout(ClientRealm* cr, int keepAliveTimeout);
void ClientRealm_set_clientMode(ClientRealm* cr, int clientMode);
void ClientRealm_set_ipFamily(ClientRealm* cr, char ipFamily);
void ClientRealm_set_realmType(ClientRealm* cr, char realmType);
void ClientRealm_set_tunnelType(ClientRealm* cr, char tunnelType);
void ClientRealm_set_keepAlive(ClientRealm* cr, struct timeval keepAlive);
void ClientRealm_set_addressLength(ClientRealm* cr, socklen_t addressLength);
void ClientRealm_set_clientAddress(ClientRealm* cr, struct sockaddr* clientAddress);
void ClientRealm_set_masterSslFd(ClientRealm* cr, SslFd* masterSslFd);
void ClientRealm_set_httpProxyOptions(ClientRealm* cr, HttpProxyOptions* httpProxyOptions);
void ClientRealm_set_arOptions(ClientRealm* cr, ArOptions* arOptions);
void ClientRealm_set_destinationPorts(ClientRealm* cr, PortList* destinationPorts);
void ClientRealm_set_usersTable(ClientRealm* cr, ConnectUser** usersTable);
#ifdef HAVE_LIBDL
void ClientRealm_set_userModule(ClientRealm* cr, Module* userModule);
void ClientRealm_set_serviceModule(ClientRealm* cr, Module* serviceModule);
#endif
/* getters */
char* ClientRealm_get_serverName(ClientRealm* cr);
char* ClientRealm_get_managePort(ClientRealm* cr);
char* ClientRealm_get_hostName(ClientRealm* cr);
char* ClientRealm_get_realmName(ClientRealm* cr);
char* ClientRealm_get_sKeepAliveTimeout(ClientRealm* cr);
char* ClientRealm_get_realmId(ClientRealm* cr);
char* ClientRealm_get_localName(ClientRealm* cr);
char* ClientRealm_get_localPort(ClientRealm* cr);
char* ClientRealm_get_localDestinationName(ClientRealm* cr);
unsigned char* ClientRealm_get_password(ClientRealm* cr);
int ClientRealm_get_connectedUsers(ClientRealm* cr);
int ClientRealm_get_usersLimit(ClientRealm* cr);
int ClientRealm_get_keepAliveTimeout(ClientRealm* cr);
int ClientRealm_get_clientMode(ClientRealm* cr);
char ClientRealm_get_ipFamily(ClientRealm* cr);
char ClientRealm_get_realmType(ClientRealm* cr);
char ClientRealm_get_tunnelType(ClientRealm* cr);
struct timeval ClientRealm_get_keepAlive(ClientRealm* cr);
socklen_t ClientRealm_get_addressLength(ClientRealm* cr);
struct sockaddr* ClientRealm_get_clientAddress(ClientRealm* cr);
SslFd* ClientRealm_get_masterSslFd(ClientRealm* cr);
HttpProxyOptions* ClientRealm_get_httpProxyOptions(ClientRealm* cr);
ArOptions* ClientRealm_get_arOptions(ClientRealm* cr);
PortList* ClientRealm_get_destinationPorts(ClientRealm* cr);
ConnectUser** ClientRealm_get_usersTable(ClientRealm* cr);
#ifdef HAVE_LIBDL
Module* ClientRealm_get_userModule(ClientRealm* cr);
Module* ClientRealm_get_serviceModule(ClientRealm* cr);
#endif
/* other */
void ClientRealm_increase_connectedUsers(ClientRealm* cr);
void ClientRealm_decrease_connectedUsers(ClientRealm* cr);
void ClientRealm_closeUsersConnections(ClientRealm* cr);
struct timeval* ClientRealm_get_keepAlivePointer(ClientRealm* cr);
void ClientRealm_send_realmId(ClientRealm* cr, unsigned char* buff);
void ClientRealm_enable_multi(ClientRealm* cr);

#endif

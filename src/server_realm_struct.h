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

#include "activefor.h"

#ifndef _JS_SERVER_REALM_STRUCT_H
#define _JS_SERVER_REALM_STRUCT_H

typedef struct {
  char* hostName;
  char* sUsersLimit;
  char* sClientsLimit;
  char* sRaClientsLimit;
  char* sUsersPerClient;
  char* sClientMode;
  char* sTimeout;
  char* realmName;
  unsigned char password[4];
  int connectedUsers;
  int usersLimit;
  int connectedClients;
  int clientsLimit;
  int connectedRaClients;
  int raClientsLimit;
  int usersPerClient;
  int timeout;
  int clientMode;
  int userClientPairs;
  int clientsCounter;
  int usersCounter;
  char realmType;
  char tunnelType;
  char dnsLookupsOn;
  char basePortOn;
  char auditOn;
  socklen_t addressLength;
  struct sockaddr* clientAddress;
  ConnectUser** usersTable;
  ConnectClient** clientsTable;
  ConnectClient** raClientsTable;
  UsrCli** usersClientsTable;
} ServerRealm;

/* 'constructor' */
ServerRealm* ServerRealm_new();
/* 'destructor' */
void ServerRealm_free(ServerRealm** sr);
/* setters */
void ServerRealm_set_hostName(ServerRealm* sr, char* hostName);
void ServerRealm_set_sUsersLimit(ServerRealm* sr, char* sUsersLimit);
void ServerRealm_set_sClientsLimit(ServerRealm* sr, char* sClientsLimit);
void ServerRealm_set_sRaClientsLimit(ServerRealm* sr, char* sRaClientsLimit);
void ServerRealm_set_sUsersPerClient(ServerRealm* sr, char* sUsersPerClient);
void ServerRealm_set_sClientMode(ServerRealm* sr, char* sClientMode);
void ServerRealm_set_sTimeout(ServerRealm* sr, char* sTimeout);
void ServerRealm_set_realmName(ServerRealm* sr, char* realmName);
void ServerRealm_set_password(ServerRealm* sr, unsigned char* password);
void ServerRealm_set_connectedUsers(ServerRealm* sr, int connectedUsers);
void ServerRealm_set_usersLimit(ServerRealm* sr, int usersLimit);
void ServerRealm_set_connectedClients(ServerRealm* sr, int connectedClients);
void ServerRealm_set_clientsLimit(ServerRealm* sr, int clientsLimit);
void ServerRealm_set_connectedRaClients(ServerRealm* sr, int connectedRaClients);
void ServerRealm_set_raClientsLimit(ServerRealm* sr, int raClientsLimit);
void ServerRealm_set_usersPerClient(ServerRealm* sr, int usersPerClient);
void ServerRealm_set_timeout(ServerRealm* sr, int timeout);
void ServerRealm_set_clientMode(ServerRealm* sr, int clientMode);
void ServerRealm_set_userClientPairs(ServerRealm* sr, int userClientPairs);
void ServerRealm_set_clientsCounter(ServerRealm* sr, int clientsCounter);
void ServerRealm_set_usersCounter(ServerRealm* sr, int usersCounter);
void ServerRealm_set_realmType(ServerRealm* sr, char realmType);
void ServerRealm_set_tunnelType(ServerRealm* sr, char tunnelType);
void ServerRealm_set_dnsLookupsOn(ServerRealm* sr, char dnsLookupsOn);
void ServerRealm_set_basePortOn(ServerRealm* sr, char basePortOn);
void ServerRealm_set_auditOn(ServerRealm* sr, char auditOn);
void ServerRealm_set_addressLength(ServerRealm* sr, socklen_t addressLength);
void ServerRealm_set_clientAddress(ServerRealm* sr, struct sockaddr* clientAddress);
void ServerRealm_set_usersTable(ServerRealm* sr, ConnectUser** usersTable);
void ServerRealm_set_clientsTable(ServerRealm* sr, ConnectClient** clientsTable);
void ServerRealm_set_raClientsTable(ServerRealm* sr, ConnectClient** raClientsTable);
void ServerRealm_set_usersClientsTable(ServerRealm* sr, UsrCli** usersClientsTable);
/* getters */
char* ServerRealm_get_hostName(ServerRealm* sr);
char* ServerRealm_get_sUsersLimit(ServerRealm* sr);
char* ServerRealm_get_sClientsLimit(ServerRealm* sr);
char* ServerRealm_get_sRaClientsLimit(ServerRealm* sr);
char* ServerRealm_get_sUsersPerClient(ServerRealm* sr);
char* ServerRealm_get_sClientMode(ServerRealm* sr);
char* ServerRealm_get_sTimeout(ServerRealm* sr);
char* ServerRealm_get_realmName(ServerRealm* sr);
unsigned char* ServerRealm_get_password(ServerRealm* sr);
int ServerRealm_get_connectedUsers(ServerRealm* sr);
int ServerRealm_get_usersLimit(ServerRealm* sr);
int ServerRealm_get_connectedClients(ServerRealm* sr);
int ServerRealm_get_clientsLimit(ServerRealm* sr);
int ServerRealm_get_connectedRaClients(ServerRealm* sr);
int ServerRealm_get_raClientsLimit(ServerRealm* sr);
int ServerRealm_get_usersPerClient(ServerRealm* sr);
int ServerRealm_get_timeout(ServerRealm* sr);
int ServerRealm_get_clientMode(ServerRealm* sr);
int ServerRealm_get_userClientPairs(ServerRealm* sr);
int ServerRealm_get_clientsCounter(ServerRealm* sr);
int ServerRealm_get_usersCounter(ServerRealm* sr);
char ServerRealm_get_realmType(ServerRealm* sr);
char ServerRealm_get_tunnelType(ServerRealm* sr);
char ServerRealm_get_dnsLookupsOn(ServerRealm* sr);
char ServerRealm_get_basePortOn(ServerRealm* sr);
char ServerRealm_get_auditOn(ServerRealm* sr);
socklen_t ServerRealm_get_addressLength(ServerRealm* sr);
struct sockaddr* ServerRealm_get_clientAddress(ServerRealm* sr);
ConnectUser** ServerRealm_get_usersTable(ServerRealm* sr);
ConnectClient** ServerRealm_get_clientsTable(ServerRealm* sr);
ConnectClient** ServerRealm_get_raClientsTable(ServerRealm* sr);
UsrCli** ServerRealm_get_usersClientsTable(ServerRealm* sr);
/* other */
void ServerRealm_increase_connectedUsers(ServerRealm* sr);
void ServerRealm_decrease_connectedUsers(ServerRealm* sr);
void ServerRealm_increase_connectedClients(ServerRealm* sr);
void ServerRealm_decrease_connectedClients(ServerRealm* sr);
void ServerRealm_increase_connectedRaClients(ServerRealm* sr);
void ServerRealm_decrease_connectedRaClients(ServerRealm* sr);
void ServerRealm_increase_usersCounter(ServerRealm* sr);
void ServerRealm_increase_clientsCounter(ServerRealm* sr);

#endif

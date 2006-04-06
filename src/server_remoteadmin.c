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
#include <assert.h>

#include "server_remoteadmin.h"

static char newmessage;

/*
 * Function name: parse_int
 * Description: This function parses the string as an integer and updates the buffer's
 *              parse pointer.
 * Arguments: buff - string to parse
 *            ret - buffer's parse pointer
 * Returns: Parsed integer value or -1, if something went wrong.
 */

static int
parse_int(unsigned char* buff, int* ret)
{
  int intarg, i;
  char guard;
  
  assert(buff != NULL);
  assert(ret != NULL);
  
  if (((i = sscanf((char*) &buff[*ret], "%d%c", &intarg, &guard)) == 2) || (i == 1)) {
    if (i == 1) {
      guard = ' ';
    }
    if (!isspace(guard)) {
      return -1;
    }
    guard = 0;
    i = (*ret);
    while (buff[i] != 0) {
      if (guard == 0) {
        if (isspace(buff[i])) {
          guard = 1;
        }
      }
      else {
        if (!isspace(buff[i])) {
          break;
        }
      }
      ++i;
    }
    if (buff[i] == '.') {
      ++i;
    }
    (*ret) = i;
    return intarg;
  }
  else {
    return -1;
  }
}

/*
 * Function name: parse_cmd
 * Description: This function parses the string as a command and updates the buffer's
 *              parse pointer.
 * Arguments: buff - string to parse
 *            ret - buffer's parse pointer
 * Returns: Parsed command number or 0, if something went wrong.
 */

static int
parse_cmd(unsigned char* buff, int* ret)
{
  int i, j, state;
  char cmd[31];
  
  assert(buff != NULL);
  assert(ret != NULL);

  i = j = state = 0;
  newmessage = 1;
  while (buff[i] != 0) {
    if (state == 1) {
      if (isspace(buff[i])) {
        break;
      }
      else {
        if (j == 30) {
          return 0;
        }
        cmd[j] = buff[i];
        ++j;
      }
    }
    if (state == 0) {
      if (!isspace(buff[i])) {
        cmd[j] = buff[i];
        j = 1;
        state = 1;
      }
    }
    ++i;
  }
  if (state == 0) {
    return 0;
  }
  while (isspace(buff[i])) {
    ++i;
  }
  if (buff[i] == '.') {
    ++i;
  }
  (*ret) = i;
  cmd[j] = 0;
  if (strcmp(cmd, "help") == 0) { return 1; }
  if (strcmp(cmd, "lcmd") == 0) { return 2; }
  if (strcmp(cmd, "info") == 0) { return 3; }
  if (strcmp(cmd, "rshow") == 0) { return 4; }
  if (strcmp(cmd, "cshow") == 0) { return 5; }
  if (strcmp(cmd, "ushow") == 0) { return 6; }
  if (strcmp(cmd, "quit") == 0) { return 7; }
  if (strcmp(cmd, "timeout") == 0) { return 8; }
  if (strcmp(cmd, "audit") == 0) { return 9; }
  if (strcmp(cmd, "dnslookups") == 0) { return 10; }
  if (strcmp(cmd, "dateformat") == 0) { return 11; }
  if (strcmp(cmd, "kuser") == 0) { return 12; }
  if (strcmp(cmd, "kclient") == 0) { return 13; }
  return 0;
}

/*
 * Function name: send_adm_message
 * Description: Sends the message via the network.
 * Arguments: type - the type of the connection
 *            master - pointer to SslFd structure
 *            buff - the message to send
 *            st - the result of the command
 */

static void
send_adm_message(char type, SslFd* master, unsigned char* buff, unsigned char st)
{
  int n;
  
  assert(master != NULL);
  assert(buff != NULL);
  
  if (!newmessage) {
    n = strlen((char*) &buff[5]);
  }
  else {
    n = 0;
  }
  buff[0] = AF_S_ADMIN_CMD;
  buff[1] = st;
  buff[2] = AF_RA_UNDEFINED;
  buff[3] = n >> 8; /* high bits of message length */
  buff[4] = n;    /* low bits of message length */
  SslFd_send_message(type, master, buff, n+5);
}

/*
 * Function name: add_to_message
 * Description: Adds text to the message.
 * Arguments: buff - the message we are adding text to
 *            format - the format of the text
 *            ... - additional arguments
 */

static void
add_to_message(unsigned char* buff, const char* format, ...)
{
  va_list ap;
  int n;
  
  assert(buff != NULL);
  assert(format != NULL);
  
  if (!newmessage) {
    n = strlen((char*) &buff[5]);
  }
  else {
    n = 0;
  }
  newmessage = 0;
  va_start(ap, format);

  vsprintf((char*) &buff[5+n], format, ap);
  n = strlen((char*) &buff[5]);
  sprintf((char*) &buff[5+n], "\n");
  
  va_end(ap);
}

/*
 * Function name: add_uptime_to_message
 * Description: Adds the formatted time period to the message.
 * Arguments: buff - the message we are adding formatted time period to
 *            info - the info which will be added to the message just before the time
 *            period - the time period we are adding to the message
 */

static void
add_uptime_to_message(unsigned char* buff, char* info, time_t period)
{
  int hours, minutes, seconds;

  assert(buff != NULL);
  assert(info != NULL);

  hours = period/3600;
  minutes = (period/60)%60;
  seconds = period%60;
 
  if (hours) {
    add_to_message(buff, "%s: %d:%02d:%02d", info, hours, minutes, seconds);
  }
  else {
    add_to_message(buff, "%s: %d:%02d", info, minutes, seconds);
  }
}

/*
 * Function name: serve_admin
 * Description: Function responsible for the reaction for user's admin commands.
 * Arguments: config - the server configuration
 *            realm - the realm number
 *            client - the client number
 *            buff - buffer containing the user's command
 * Returns: 0 - do nothing,
 *          1 - kick this client,
 *          >1 - kick the specified client.
 */

int
serve_admin(ServerConfiguration* config, int realm, int client, unsigned char* buff)
{
  int length, n, i, j, ret;
  time_t now, tmp;
  llnodeT* llptr;
  AuditListNode* alptr;
  char olddf[51], newdf[51];
  ConnectClient* cpointer;
  ConnectUser* upointer;
  ServerRealm* pointer = ServerConfiguration_get_realmsTable(config)[realm];
  char type = ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB;
  SslFd* master = ConnectClient_get_sslFd(ServerRealm_get_raClientsTable(pointer)[client]);
 
  assert(config != NULL);
  assert(buff != NULL);
  
  olddf[50] = newdf[50] = 0;
  length = buff[3];
  length = length << 8;
  length += buff[4]; /* this is the length of a message */
  
  time(&now);
  
  switch (buff[1]) {
    case AF_RA_CMD: {
                      n = SslFd_get_message(type, master, buff, length);
                      buff[n] = 0;
                      aflog(LOG_T_MANAGE, LOG_I_INFO,
                          "realm[%s]: admin: message length = %d [%s]",
                          get_realmname(config, realm), n, buff);
                      switch (parse_cmd(buff, &ret)) {
                        case 1: { /* help */
                                  add_to_message(buff, AF_VER("AFSERVER"));
                                  add_to_message(buff, "\nValid commands are:");
                                  add_to_message(buff, "  help                 display help");
                                  add_to_message(buff, "  lcmd                 lists available commands");
                                  add_to_message(buff, "  info                 prints info about server");
                                  add_to_message(buff, "  rshow                display realms");
                                  add_to_message(buff, "  cshow X              display clients in X realm");
                                  add_to_message(buff, "  ushow X              display users in X realm");
                                  add_to_message(buff, "  quit                 quit connection");
                                  add_to_message(buff, "  timeout N X          set timeout value in X realm");
                                  add_to_message(buff, "  audit {0|1} X        set audit mode in X realm");
                                  add_to_message(buff, "  dnslookups {0|1} X   set dnslookups mode in X realm");
                                  add_to_message(buff, "  dateformat S         set dateformat");
                                  add_to_message(buff, "  kuser S              kick user named S");
                                  add_to_message(buff, "  kclient N            kick client with number N");
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 2: { /* lcmd */
                                  add_to_message(buff, "help");
                                  add_to_message(buff, "lcmd");
                                  add_to_message(buff, "info");
                                  add_to_message(buff, "rshow");
                                  add_to_message(buff, "cshow");
                                  add_to_message(buff, "ushow");
                                  add_to_message(buff, "quit");
                                  add_to_message(buff, "timeout");
                                  add_to_message(buff, "audit");
                                  add_to_message(buff, "dnslookups");
                                  add_to_message(buff, "dateformat");
                                  add_to_message(buff, "kuser");
                                  add_to_message(buff, "kclient");
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 3: { /* info */
                                  add_to_message(buff, AF_VER("Version:"));
                                  add_to_message(buff, "Realms: %d",
                                      ServerConfiguration_get_realmsNumber(config));
                                  add_to_message(buff, "Certificate: %s",
                                      ServerConfiguration_get_certificateFile(config));
                                  add_to_message(buff, "Key: %s",
                                      ServerConfiguration_get_keysFile(config));
                                  llptr = getloglisthead();
                                  i = 0;
                                  while (llptr) {
                                    add_to_message(buff, "log[%d]: %s", i, llptr->cmdline);
                                    llptr = llptr->next;
                                    ++i;
                                  }
                                  tmp = now - ServerConfiguration_get_startTime(config);
                                  add_uptime_to_message(buff, "Uptime", tmp);
                                  add_to_message(buff, "Cg: %ld B", getcg());
                                  add_to_message(buff, "Dateformat: %s", getdateformat());
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 4: { /* rshow */
                                  for (i = 0; i < ServerConfiguration_get_realmsNumber(config); ++i) {
                                    pointer = ServerConfiguration_get_realmsTable(config)[i];
                                    add_to_message(buff, "\nRealm[%s]:", get_realmname(config, i));
                                    add_to_message(buff, "hostname: %s", ServerRealm_get_hostName(pointer));
                                    add_to_message(buff, "users: %d (max: %d)",
                                        ServerRealm_get_connectedUsers(pointer),
                                        ServerRealm_get_usersLimit(pointer));
                                    add_to_message(buff, "clients: %d (max: %d)",
                                        ServerRealm_get_connectedClients(pointer) -
                                        ServerRealm_get_connectedRaClients(pointer),
                                        ServerRealm_get_clientsLimit(pointer));
                                    add_to_message(buff, "raclients: %d (max: %d)",
                                        ServerRealm_get_connectedRaClients(pointer),
                                        ServerRealm_get_raClientsLimit(pointer));
                                    add_to_message(buff, "users per client: %s",
                                        ServerRealm_get_sUsersPerClient(pointer));
                                    add_to_message(buff, "user-client pairs: %d",
                                        ServerRealm_get_userClientPairs(pointer));
                                    for (j = 0; j < ServerRealm_get_userClientPairs(pointer); ++j) {
                                      add_to_message(buff, " pair[%d]: listenport: %s, manageport: %s", j,
                                          UsrCli_get_listenPortName(
                                            ServerRealm_get_usersClientsTable(pointer)[j]),
                                          UsrCli_get_managePortName(
                                            ServerRealm_get_usersClientsTable(pointer)[j]));
                                    }
                                    add_to_message(buff, "climode: %s", ServerRealm_get_sClientMode(pointer));
                                    add_to_message(buff, "timeout: %d", ServerRealm_get_timeout(pointer));
                                    if (ServerRealm_get_maxIdle(pointer)) {
                                      add_to_message(buff, "max idle: %d", ServerRealm_get_maxIdle(pointer));
                                    }
                                    else {
                                      add_to_message(buff, "max idle: disabled");
                                    }
                                    add_to_message(buff, "baseport: %s", ServerRealm_get_basePortOn(pointer) ?
                                        "yes" : "no");
                                    add_to_message(buff, "audit: %s", ServerRealm_get_auditOn(pointer) ?
                                        "yes" : "no");
                                    add_to_message(buff, "dnslookups: %s",
                                        ServerRealm_get_dnsLookupsOn(pointer) ? "yes" : "no");
                                    add_to_message(buff, "ssl: %s, zlib: %s, mode: %s",
                                        (TYPE_IS_SSL(ServerRealm_get_realmType(pointer))) ? "yes" : "no",
                                        (TYPE_IS_ZLIB(ServerRealm_get_realmType(pointer))) ? "yes" : "no",
                                        (TYPE_IS_TCP(ServerRealm_get_realmType(pointer))) ? "tcp" : "udp");
                                    switch (ServerRealm_get_tunnelType(pointer)) {
                                      case CONNECTCLIENT_TUNNELTYPE_DIRECT: {
                                                add_to_message(buff, "tunneltype: direct");
                                                break;
                                              }
                                      case CONNECTCLIENT_TUNNELTYPE_HTTPPROXY: {
                                                add_to_message(buff, "tunneltype: http proxy");
                                                break;
                                              }
                                      case CONNECTCLIENT_TUNNELTYPE_HTTPSPROXY: {
                                                add_to_message(buff, "tunneltype: https proxy");
                                                break;
                                              }
                                      default: {
                                                 add_to_message(buff, "tunneltype: UNKNOWN");
                                               }
                                    }
                                  }
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 5: { /* cshow*/
                                  n = get_realmnumber(config, (char*) &buff[ret]);
                                  if ((n >= 0) && (n < ServerConfiguration_get_realmsNumber(config))) {
                                    pointer = ServerConfiguration_get_realmsTable(config)[n];
                                    for (i = 0; i < ServerRealm_get_clientsLimit(pointer); ++i) {
                                      cpointer = ServerRealm_get_clientsTable(pointer)[i];
                                      if (ConnectClient_get_state(cpointer) != CONNECTCLIENT_STATE_FREE) {
                                        add_to_message(buff, "\nClient[%s]:",
                                            get_clientname(pointer, i));
                                        switch (ConnectClient_get_state(cpointer)) {
                                          case CONNECTCLIENT_STATE_CONNECTING: {
                                                    add_to_message(buff, "state: ssl handshake");
                                                    break;
                                                  }
                                          case CONNECTCLIENT_STATE_AUTHORIZING: {
                                                    add_to_message(buff, "state: authorization");
                                                    break;
                                                  }
                                          case CONNECTCLIENT_STATE_ACCEPTED: {
                                                    add_to_message(buff, "state: running");
                                                    break;
                                                  }
                                          default: {
                                                    add_to_message(buff, "state: unknown");
                                                   }
                                        }
                                        add_to_message(buff, "users: %d (max: %d)",
                                            ConnectClient_get_connected(cpointer),
                                            ConnectClient_get_limit(cpointer));
                                        add_to_message(buff, "user-client pair: %d",
                                            ConnectClient_get_usrCliPair(cpointer)); 
                                        tmp = now - ConnectClient_get_connectTime(cpointer);
                                        add_uptime_to_message(buff, "Connection time", tmp);
                                        tmp = now - ConnectClient_get_lastActivity(cpointer);
                                        add_uptime_to_message(buff, "Idle time", tmp);
                                        add_to_message(buff, "Id: %s",
                                            (ConnectClient_get_sClientId(cpointer) == NULL) ? "" :
                                            ConnectClient_get_sClientId(cpointer));
                                        add_to_message(buff, "Number: %d",
                                            ConnectClient_get_clientId(cpointer));
                                        add_to_message(buff, "IP: %s, port: %s",
                                            ConnectClient_get_nameBuf(cpointer),
                                            ConnectClient_get_portBuf(cpointer));
                                        switch (ConnectClient_get_tunnelType(cpointer)) {
                                          case CONNECTCLIENT_TUNNELTYPE_DIRECT: {
                                                    add_to_message(buff, "tunneltype: direct");
                                                    break;
                                                  }
                                          case CONNECTCLIENT_TUNNELTYPE_HTTPPROXY: {
                                                    add_to_message(buff, "tunneltype: http proxy");
                                                    break;
                                                  }
                                          case CONNECTCLIENT_TUNNELTYPE_HTTPSPROXY: {
                                                    add_to_message(buff, "tunneltype: https proxy");
                                                    break;
                                                  }
                                          default: {
                                                     add_to_message(buff, "tunneltype: UNKNOWN");
                                                   }
                                        }
                                        if (ServerRealm_get_auditOn(pointer)) {
                                          add_to_message(buff, "auditlog:");
                                          alptr = AuditList_get_first(
                                              ConnectClient_get_auditList(cpointer));
                                          while (alptr) {
                                            add_to_message(buff,
                                                "userid: %d ip: %s port: %s connected: %s duration: %s",
                                                AuditListNode_get_userId(alptr),
                                                AuditListNode_get_nameBuf(alptr),
                                                AuditListNode_get_portBuf(alptr),
                                                localdate(AuditListNode_get_connectTimep(alptr)),
                                                timeperiod(AuditListNode_get_duration(alptr)));
                                            alptr = AuditListNode_get_nextNode(alptr);
                                          }
                                        }
                                      }
                                    }
                                    send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                    break;
                                  }
                                  add_to_message(buff, "Wrong realm name");
                                  add_to_message(buff, "Usage: cshow X      , X - realm name");
                                  send_adm_message(type, master, buff, AF_RA_FAILED);
                                  break;
                                }
                        case 6: { /* ushow */
                                  n = get_realmnumber(config, (char*) &buff[ret]);
                                  if ((n >= 0) && (n < ServerConfiguration_get_realmsNumber(config))) {
                                    pointer = ServerConfiguration_get_realmsTable(config)[n];
                                    for (i = 0; i < ServerRealm_get_usersLimit(pointer); ++i) {
                                      upointer = ServerRealm_get_usersTable(pointer)[i];
                                      if (ConnectUser_get_state(upointer) != S_STATE_CLEAR) {
                                        add_to_message(buff, "\nUser[%d]:",
                                            get_username(pointer, i));
                                        switch (ConnectUser_get_state(upointer)) {
                                          case S_STATE_CLOSING: {
                                                    add_to_message(buff, "state: closing");
                                                    break;
                                                  }
                                          case S_STATE_OPENING: {
                                                    add_to_message(buff, "state: opening");
                                                    break;
                                                  }
                                          case S_STATE_OPENING_CLOSED: {
                                                    add_to_message(buff, "state: opening (closed)");
                                                    break;
                                                  }
                                          case S_STATE_OPEN: {
                                                    add_to_message(buff, "state: running");
                                                    break;
                                                  }
                                          case S_STATE_STOPPED: {
                                                    add_to_message(buff, "state: stopped");
                                                    break;
                                                  }
                                          default: {
                                                    add_to_message(buff, "state: unknown");
                                                   }
                                        }
                                        add_to_message(buff, "connected to: Client[%s]",
                                            get_clientname(pointer, ConnectUser_get_whatClient(upointer)));
                                        tmp = now-ConnectUser_get_connectTime(upointer);
                                        add_uptime_to_message(buff, "Connection time", tmp);
                                        tmp = now - UserStats_get_lastActivity(
                                            ConnectUser_get_stats(upointer));
                                        add_uptime_to_message(buff, "Idle time", tmp);
                                        add_to_message(buff, "IP: %s, port: %s",
                                            ConnectUser_get_nameBuf(upointer),
                                            ConnectUser_get_portBuf(upointer));
                                        add_to_message(buff, "Downloaded: %d bytes",
                                            UserStats_get_totalDownloadedBytes(
                                              ConnectUser_get_stats(upointer)));
                                        add_to_message(buff, "download speed: %.2f B/s",
                                            UserStats_get_downloadSpeed(
                                              ConnectUser_get_stats(upointer)));
                                        add_to_message(buff, "Uploaded: %d bytes",
                                            UserStats_get_totalUploadedBytes(
                                              ConnectUser_get_stats(upointer)));
                                        add_to_message(buff, "upload speed: %.2f B/s",
                                            UserStats_get_uploadSpeed(
                                              ConnectUser_get_stats(upointer)));
                                      }
                                    }
                                    send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                    break;
                                  }
                                  add_to_message(buff, "Wrong realm name");
                                  add_to_message(buff, "Usage: ushow X      , X - realm name");
                                  send_adm_message(type, master, buff, AF_RA_FAILED);
                                  break;
                                }
                        case 7: { /* quit */
                                  aflog(LOG_T_MANAGE, LOG_I_INFO,
                                      "realm[%s]: Client[%s] (ra): commfd: CLOSED",
                                      get_realmname(config, realm),
                                      get_raclientname(pointer, client));
                                  send_adm_message(type, master, buff, AF_RA_KICKED);
                                  return 1;
                                }
                        case 8: { /* timeout */
                                  i = parse_int(buff, &ret);
                                  if (i <= 0) {
                                    add_to_message(buff, "Invalid timeout value");
                                    add_to_message(buff,
                                        "Usage: timeout N X      , N - new timeout value, X - realm name");
                                    send_adm_message(type, master, buff, AF_RA_FAILED);
                                    break;
                                  }
                                  n = get_realmnumber(config, (char*) &buff[ret]);
                                  if ((n >= 0) && (n < ServerConfiguration_get_realmsNumber(config))) {
                                    add_to_message(buff, "changed timeout: %d --> %d",
                                        ServerRealm_get_timeout(
                                          ServerConfiguration_get_realmsTable(config)[n]), i);
                                    ServerRealm_set_timeout(ServerConfiguration_get_realmsTable(config)[n], i);
                                    send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                    break;
                                  }
                                  add_to_message(buff, "Wrong realm name");
                                  add_to_message(buff,
                                      "Usage: timeout N X      , N - new timeout value, X - realm name");
                                  send_adm_message(type, master, buff, AF_RA_FAILED);
                                  break;
                                }
                        case 9: { /* audit */
                                  i = parse_int(buff, &ret);
                                  if ((i != 0) && (i != 1)) {
                                    add_to_message(buff, "Invalid audit value");
                                    add_to_message(buff,
                                        "Usage: audit {0|1} X      , N=0 off, N=1 on, X - realm name");
                                    send_adm_message(type, master, buff, AF_RA_FAILED);
                                    break;
                                  }
                                  n = get_realmnumber(config, (char*) &buff[ret]);
                                  if ((n >= 0) && (n < ServerConfiguration_get_realmsNumber(config))) {
                                    add_to_message(buff, "changed audit: %s --> %s",
                                        ServerRealm_get_auditOn(
                                          ServerConfiguration_get_realmsTable(config)[n]) ? "yes" : "no",
                                        i ? "yes" : "no");
                                    ServerRealm_set_auditOn(ServerConfiguration_get_realmsTable(config)[n], i);
                                    if (i == 0) {
                                      for (i = 0; i < ServerRealm_get_clientsLimit(
                                            ServerConfiguration_get_realmsTable(config)[n]); ++i) {
                                        AuditList_clear(
                                            ConnectClient_get_auditList(
                                              ServerRealm_get_clientsTable(
                                                ServerConfiguration_get_realmsTable(config)[n])[i]));
                                      }
                                    }
                                    send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                    break;
                                  }
                                  add_to_message(buff, "Wrong realm name");
                                  add_to_message(buff,
                                      "Usage: audit {0|1} X      , N=0 off, N=1 on, X - realm name");
                                  send_adm_message(type, master, buff, AF_RA_FAILED);
                                  break;
                                }
                        case 10: { /* dnslookups */
                                  i = parse_int(buff, &ret);
                                  if ((i != 0) && (i != 1)) {
                                    add_to_message(buff, "Invalid dnslookups value");
                                    add_to_message(buff,
                                        "Usage: dnslookups {0|1} X      , N=0 off, N=1 on, X - realm name");
                                    send_adm_message(type, master, buff, AF_RA_FAILED);
                                    break;
                                  }
                                  n = get_realmnumber(config, (char*) &buff[ret]);
                                  if ((n >= 0) && (n < ServerConfiguration_get_realmsNumber(config))) {
                                    add_to_message(buff, "changed dnslookups: %s --> %s",
                                        ServerRealm_get_dnsLookupsOn(
                                          ServerConfiguration_get_realmsTable(config)[n]) ? "yes" : "no",
                                        i ? "yes" : "no");
                                    ServerRealm_set_dnsLookupsOn(
                                        ServerConfiguration_get_realmsTable(config)[n], i);
                                    send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                    break;
                                  }
                                  add_to_message(buff, "Wrong realm name");
                                  add_to_message(buff,
                                      "Usage: dnslookups {0|1} X      , N=0 off, N=1 on, X - realm name");
                                  send_adm_message(type, master, buff, AF_RA_FAILED);
                                  break;
                                }
                        case 11: { /* dateformat */
                                  strncpy(olddf, getdateformat(), 50);
                                  strncpy(newdf, (char*) &buff[ret], 50);
                                  add_to_message(buff, "changed dateformat: %s --> %s",
                                      olddf, newdf);
                                  setdateformat(newdf);
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 12: { /* kuser */
                                  i = parse_int(buff, &ret);
                                  if (buff[ret] != 0) {
                                    add_to_message(buff, "Invalid user name");
                                    add_to_message(buff,
                                        "Usage: kuser S      , S - user name");
                                    send_adm_message(type, master, buff, AF_RA_FAILED);
                                    break;
                                  }
                                  j = -1;
                                  for (n = 0; n < ServerConfiguration_get_realmsNumber(config); ++n) {
                                    pointer = ServerConfiguration_get_realmsTable(config)[n];
                                    j = get_usernumber(pointer, i);
                                    if (j != (-1)) {
                                      upointer = ServerRealm_get_usersTable(pointer)[j];
                                      if ((ConnectUser_get_state(upointer) == S_STATE_OPEN) ||
                                          (ConnectUser_get_state(upointer) == S_STATE_OPENING) ||
                                          (ConnectUser_get_state(upointer) == S_STATE_STOPPED)) {
                                        add_to_message(buff, "kicked: realm[%s] user[%d]",
                                            get_realmname(config, n), get_username(pointer, j));
                                        if (ConnectUser_get_state(upointer) == S_STATE_OPENING) {
                                          ConnectUser_set_state(upointer, S_STATE_OPENING_CLOSED);
                                        }
                                        else {
                                          close(ConnectUser_get_connFd(upointer));
                                        }
                                        send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                      }
                                      else {
                                        add_to_message(buff, "Invalid user");
                                        add_to_message(buff,
                                            "Usage: kuser S      , S - user name");
                                        send_adm_message(type, master, buff, AF_RA_FAILED);
                                      }
                                      break;
                                    }
                                  }
                                  if (j == (-1)) {
                                    add_to_message(buff, "Invalid user name");
                                    add_to_message(buff,
                                        "Usage: kuser S      , S - user name");
                                    send_adm_message(type, master, buff, AF_RA_FAILED);
                                  }
                                  break;
                                }
                        case 13: { /* kclient */
                                  i = parse_int(buff, &ret);
                                  if (buff[ret] != 0) {
                                    add_to_message(buff, "Invalid client number");
                                    add_to_message(buff,
                                        "Usage: kclient N      , N - client number");
                                    send_adm_message(type, master, buff, AF_RA_FAILED);
                                    break;
                                  }
                                  j = -1;
                                  for (n = 0; n < ServerConfiguration_get_realmsNumber(config); ++n) {
                                    pointer = ServerConfiguration_get_realmsTable(config)[n];
                                    j = get_clientnumber(pointer, i);
                                    if (j != (-1)) {
                                      if (ConnectClient_get_state(ServerRealm_get_clientsTable(pointer)[j]) >
                                          CONNECTCLIENT_STATE_FREE) {
                                        add_to_message(buff, "kicked: realm[%s] client[%s]",
                                            get_realmname(config, n),
                                            get_clientname(pointer, j));
                                        send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                        return (i+2);
                                      }
                                      else {
                                        add_to_message(buff, "Invalid client");
                                        add_to_message(buff,
                                            "Usage: kclient N      , N - client number");
                                        send_adm_message(type, master, buff, AF_RA_FAILED);
                                      }
                                      break;
                                    }
                                  }
                                  if (j == (-1)) {
                                    add_to_message(buff, "Invalid client number");
                                    add_to_message(buff,
                                        "Usage: kclient N      , N - client number");
                                    send_adm_message(type, master, buff, AF_RA_FAILED);
                                  }
                                  break;

                                }
                        default: {
                                  aflog(LOG_T_MANAGE, LOG_I_WARNING,
                                      "realm[%s]: admin: cmd ignored", get_realmname(config, realm));
                                  send_adm_message(type, master, buff, AF_RA_UNDEFINED);
                                 }
                      }
                      break;
                    }
    case AF_RA_REPEAT: {
                         break;
                       }
    default: {
               aflog(LOG_T_MANAGE, LOG_I_ERR,
                   "Unrecognized message from remote admin --> closing");
               return 1;
             }
  }
  return 0;
}

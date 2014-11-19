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

#include "file.h"
#include "activefor.h"
#include "logging.h"
#include "network.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

/*
 * Function name: parsefile
 * Description: Parses the server config file.
 * Arguments: name - the name of the file with client's config
 *            status - the status returned from this function:
 *                     0 - file was parsed successfully
 *                     n>0 - there was an error in the n-th line
 * Returns: Pointer to ServerConfiguration structure.
 */

ServerConfiguration*
parsefile(char* name, int* status)
{
  ServerConfiguration* cfg;
  FILE* file = NULL;
  int state, i, j, n, listencount, managecount, temp;
  char buff[256];
  char helpbuf1[256];
  char helpbuf2[256];
  char* tmpbuf;
  unsigned char pass[4] = {1, 2, 3, 4};

  *status = 1;

  memset(buff, 0, 256);

  cfg = ServerConfiguration_new();

  if (cfg == NULL) {
    printf("Can't allocate memory for server configuration... exiting\n");
    exit(1);
  }
	
  state = F_UNKNOWN;
	
  file = fopen(name, "r");
  if (file == NULL) {
    return cfg;
  }

  while (fgets(buff, 256, file) != NULL) { /* first loop - counting realm */
    helpbuf1[0] = 0;
    parse_line(buff, helpbuf1, helpbuf2);
    if (strcmp(helpbuf1, "realm")==0) {
      ServerConfiguration_set_realmsNumber(cfg, ServerConfiguration_get_realmsNumber(cfg) + 1);
    }
  }
  rewind(file);
	
  ServerConfiguration_set_realmsTable(cfg,
      calloc(ServerConfiguration_get_realmsNumber(cfg), sizeof(ServerRealm*)));
  if (ServerConfiguration_get_realmsTable(cfg) == NULL) {
    printf("Can't allocate memory for ServerRealm* table... exiting\n");
    exit(1);
  }
  for (i = 0; i < ServerConfiguration_get_realmsNumber(cfg); ++i) {
    ServerConfiguration_get_realmsTable(cfg)[i] = ServerRealm_new();
    if (ServerConfiguration_get_realmsTable(cfg)[i] == NULL) {
      printf("Problem with allocating memory for ServerRealm structure... exiting");
      exit(1);
    }
    ServerRealm_set_password(ServerConfiguration_get_realmsTable(cfg)[i], pass);
  }
  ServerConfiguration_set_realmsNumber(cfg, 0);
  *status = 0;

  listencount = managecount = 0;
  
  
  while (fgets(buff, 256, file) != NULL) { /* second loop - counting listen */
    (*status)++;
    state = parse_line(buff, helpbuf1, helpbuf2);
    if (state) {
      if (strcmp(helpbuf1, "realm") == 0) {
        ServerConfiguration_set_realmsNumber(cfg, ServerConfiguration_get_realmsNumber(cfg) + 1);
        if (listencount != managecount) {
          return cfg;
        }
        listencount = managecount = 0;
      }
      else if ((strcmp(helpbuf1, "listen") == 0) || (strcmp(helpbuf1, "listenport") == 0)) {
        if (ServerConfiguration_get_realmsNumber(cfg) == 0) {
          return cfg;
        }
        ServerRealm_set_userClientPairs(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            ServerRealm_get_userClientPairs(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1]) +
            1);
        ++listencount;
      }
      else if ((strcmp(helpbuf1, "manage") == 0) || (strcmp(helpbuf1, "manageport") == 0)) {
        if (ServerConfiguration_get_realmsNumber(cfg) == 0) {
          return cfg;
        }
        ++managecount;
      }
    }
  }
  rewind(file);

  if (listencount != managecount) {
    return cfg;
  }

  for (i = 0; i < ServerConfiguration_get_realmsNumber(cfg); ++i) {
    ServerRealm_set_usersClientsTable(ServerConfiguration_get_realmsTable(cfg)[i],
        calloc(ServerRealm_get_userClientPairs(ServerConfiguration_get_realmsTable(cfg)[i]), sizeof(UsrCli*)));
    if (ServerRealm_get_usersClientsTable(ServerConfiguration_get_realmsTable(cfg)[i]) == NULL) {
      printf("Problem with allocating memory for UsrCli* table... exiting");
      return cfg;
    }
    for (j = 0; j < ServerRealm_get_userClientPairs(ServerConfiguration_get_realmsTable(cfg)[i]); ++j) {
      ServerRealm_get_usersClientsTable(ServerConfiguration_get_realmsTable(cfg)[i])[j] = UsrCli_new();
      if (ServerRealm_get_usersClientsTable(ServerConfiguration_get_realmsTable(cfg)[i])[j] == NULL) {
        printf("Problem with allocating memory for UsrCli structure... exiting");
        return cfg;
      }
    }
  }
  
  ServerConfiguration_set_realmsNumber(cfg, 0);
  *status = 0;
  
  
  while (fgets(buff, 256, file) != NULL) { /* third loop - parsing file */
    (*status)++;
    state = parse_line(buff, helpbuf1, helpbuf2);
    if (helpbuf1[0] == '#') {
      memset(buff, 0, 256);
      continue;
    }
    if (state == 1) {
      if (strcmp(helpbuf1, "realm")==0) {
        ServerConfiguration_set_realmsNumber(cfg, ServerConfiguration_get_realmsNumber(cfg) + 1);
        temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1]);
        TYPE_SET_SSL(temp);
        TYPE_SET_ZLIB(temp);
        TYPE_SET_SUPPORTED_MULTI(temp);
        ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
        listencount = managecount = 0;
      }
      else if (ServerConfiguration_get_realmsNumber(cfg) == 0) {
        return cfg;
      }
      else if (strcmp(helpbuf1, "nossl")==0) {
        temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1]);
        TYPE_UNSET_SSL(temp);
        ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
      }
      else if (strcmp(helpbuf1, "nozlib")==0) {
        temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1]);
        TYPE_UNSET_ZLIB(temp);
        ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
      }
      else if (strcmp(helpbuf1, "baseport")==0) {
        ServerRealm_set_basePortOn(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            1);
      }
      else if (strcmp(helpbuf1, "audit")==0) {
        ServerRealm_set_auditOn(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            1);
      }
      else if (strcmp(helpbuf1, "dnslookups")==0) {
        ServerRealm_set_dnsLookupsOn(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            1);
      }
#ifdef HAVE_LIBPTHREAD
      else if (strcmp(helpbuf1, "enableproxy")==0) {
        if (ServerRealm_get_tunnelType(
              ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1]) == 0) {
          ServerRealm_set_tunnelType(
              ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
              1);
        }
        else {
          return cfg;
        }
      }
#endif
#ifdef AF_INET6
      else if (strcmp(helpbuf1, "ipv4")==0) {
        if (TYPE_IS_UNSPEC(ServerRealm_get_realmType(
                ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1]))) {
          temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1]);
          TYPE_SET_IPV4(temp);
          ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
        }
        else {
          return cfg;
        }
      }
      else if (strcmp(helpbuf1, "ipv6")==0) {
        if (TYPE_IS_UNSPEC(ServerRealm_get_realmType(
                ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1]))) {
          temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1]);
          TYPE_SET_IPV6(temp);
          ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
        }
        else {
          return cfg;
        }
      }
#endif
      else {
        return cfg;
      }
    }
    else if (state == 2) {
      if (strcmp(helpbuf1, "realm")==0) {
        ServerConfiguration_set_realmsNumber(cfg, ServerConfiguration_get_realmsNumber(cfg) + 1);
        temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1]);
        TYPE_SET_SSL(temp);
        TYPE_SET_ZLIB(temp);
        TYPE_SET_SUPPORTED_MULTI(temp);
        ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
            ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
        listencount = managecount = 0;
        ServerRealm_set_realmName(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if ((strcmp(helpbuf1, "certificate") == 0) || (strcmp(helpbuf1, "cerfile") == 0)) {
        ServerConfiguration_set_certificateFile(cfg, helpbuf2);
      }
      else if (strcmp(helpbuf1, "cacerfile") == 0) {
        ServerRealm_set_cacertificateFile(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "cerdepth") == 0) {
        ServerRealm_set_sCertificateDepth(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if ((strcmp(helpbuf1, "key") == 0) || (strcmp(helpbuf1, "keyfile") == 0)) {
        ServerConfiguration_set_keysFile(cfg, helpbuf2);
      }
      else if (strcmp(helpbuf1, "log")==0) {
        tmpbuf = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(tmpbuf, helpbuf2);
        addlogtarget(tmpbuf);
      }
      else if (strcmp(helpbuf1, "dateformat")==0) {
        ServerConfiguration_set_dateFormat(cfg, helpbuf2);
      }
      else if (ServerConfiguration_get_realmsNumber(cfg) == 0) {
        return cfg;
      }
      else if (strcmp(helpbuf1, "hostname")==0) {
        ServerRealm_set_hostName(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if ((strcmp(helpbuf1, "listen") == 0) || (strcmp(helpbuf1, "listenport") == 0)) {
        UsrCli_set_listenPortName(
            ServerRealm_get_usersClientsTable(
              ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1])[listencount], helpbuf2);
        ++listencount;
      }
      else if (strcmp(helpbuf1, "pass")==0) {
        n = strlen(helpbuf2);
        memset(pass, 0, 4);
        for (i = 0; i < n; ++i) {
          pass[i%4] += helpbuf2[i];
        }
        ServerRealm_set_password(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            pass);
      }
      else if ((strcmp(helpbuf1, "manage") == 0) || (strcmp(helpbuf1, "manageport") == 0)) {
        UsrCli_set_managePortName(
            ServerRealm_get_usersClientsTable(
              ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1])[managecount], helpbuf2);
        ++managecount;
      }
      else if (strcmp(helpbuf1, "users")==0) {
        ServerRealm_set_sUsersLimit(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "timeout")==0) {
        ServerRealm_set_sTimeout(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "maxidle")==0) {
        ServerRealm_set_sMaxIdle(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "clients")==0) {
        ServerRealm_set_sClientsLimit(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "raclients")==0) {
        ServerRealm_set_sRaClientsLimit(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "usrpcli")==0) {
        ServerRealm_set_sUsersPerClient(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "climode")==0) {
        ServerRealm_set_sClientMode(
            ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1],
            helpbuf2);
      }
      else if (strcmp(helpbuf1, "proto")==0) {
        if (TYPE_IS_SET(ServerRealm_get_realmType(
                ServerConfiguration_get_realmsTable(cfg)[ServerConfiguration_get_realmsNumber(cfg) - 1]))) {
          return cfg;
        }
        if (strcmp(helpbuf2, "tcp")==0) {
          temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1]);
          TYPE_SET_TCP(temp);
          ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
        }
        else if (strcmp(helpbuf2, "udp")==0) {
          temp = ServerRealm_get_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1]);
          TYPE_SET_UDP(temp);
          ServerRealm_set_realmType(ServerConfiguration_get_realmsTable(cfg)[
              ServerConfiguration_get_realmsNumber(cfg) - 1], temp);
        }
        else {
          return cfg;
        }
      }
      else {
        return cfg;
      }
    }
    memset(buff, 0, 256);
  }

  fclose(file);
	
  *status = 0;
  return cfg;
}

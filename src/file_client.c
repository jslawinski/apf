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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <assert.h>

#include "file.h"
#include "activefor.h"
#include "logging.h"
#include "network.h"

/*
 * Function name: cparsefile
 * Description: Parses the client config file.
 * Arguments: name - the name of the file with client's config
 *            status - the status returned from this function:
 *                     0 - file was parsed successfully
 *                     n>0 - there was an error in the n-th line
 * Returns: Pointer to ClientConfiguration structure.
 */

ClientConfiguration*
cparsefile(char* name, int* status)
{
  ClientConfiguration* cfg;
  FILE* file = NULL;
  int state, i, n;
#ifdef AF_INET6
  int temp;
#endif
  char buff[256];
  char helpbuf1[256];
  char helpbuf2[256];
  char* tmpbuf;
  unsigned char pass[4] = {1, 2, 3, 4};

  assert(name != NULL);
  assert(status != NULL);
  
  *status = 1;

  memset(buff, 0, 256);

  cfg = ClientConfiguration_new();

  if (cfg == NULL) {
    printf("Can't allocate memory for client configuration... exiting\n");
    exit(1);
  }
	
  state = F_UNKNOWN;
	
  file = fopen(name, "r");
  if (file == NULL) {
    return cfg;
  }

  ClientConfiguration_set_realmsNumber(cfg, 1);
	
  ClientConfiguration_set_realmsTable(cfg,
      calloc(ClientConfiguration_get_realmsNumber(cfg), sizeof(ClientRealm*)));
  if (ClientConfiguration_get_realmsTable(cfg) == NULL) {
    printf("Can't allocate memory for ClientRealm* table... exiting\n");
    exit(1);
  }
  for (i = 0; i < ClientConfiguration_get_realmsNumber(cfg); ++i) {
    ClientConfiguration_get_realmsTable(cfg)[i] = ClientRealm_new();
    if (ClientConfiguration_get_realmsTable(cfg)[i] == NULL) {
      printf("Problem with allocating memory for ClientRealm structure... exiting");
      exit(1);
    }
    ClientRealm_set_password(ClientConfiguration_get_realmsTable(cfg)[i], pass);
    ClientRealm_set_destinationPorts(ClientConfiguration_get_realmsTable(cfg)[i], PortList_new());
  }
  *status = 0;
  
  while (fgets(buff, 256, file) != NULL) { /* loop - parsing file */
    (*status)++;
    state = parse_line(buff, helpbuf1, helpbuf2);
    if (helpbuf1[0] == '#') {
      memset(buff, 0, 256);
      continue;
    }
    if (state == 1) {
      if (strcmp(helpbuf1, "ignorepkeys") == 0) {
        ClientConfiguration_set_ignorePublicKeys(cfg, 1);
      }
      else if (strcmp(helpbuf1, "ar-start") == 0) {
        ArOptions_set_arStart(ClientRealm_get_arOptions(ClientConfiguration_get_realmsTable(cfg)[0]),
            AR_OPTION_ENABLED);
      }
      else if (strcmp(helpbuf1, "ar-quit") == 0) {
        ArOptions_set_arQuit(ClientRealm_get_arOptions(ClientConfiguration_get_realmsTable(cfg)[0]),
            AR_OPTION_ENABLED);
      }
      else if (strcmp(helpbuf1, "noar") == 0) {
        ArOptions_set_arPremature(ClientRealm_get_arOptions(ClientConfiguration_get_realmsTable(cfg)[0]),
            AR_OPTION_DISABLED);
      }
      else if ((strcmp(helpbuf1, "u") == 0) || (strcmp(helpbuf1, "udpmode") == 0)) {
        if (ClientRealm_get_clientMode(ClientConfiguration_get_realmsTable(cfg)[0]) == CLIENTREALM_MODE_TCP) {
          ClientRealm_set_clientMode(ClientConfiguration_get_realmsTable(cfg)[0], CLIENTREALM_MODE_UDP);
        }
        else {
          ClientRealm_set_clientMode(ClientConfiguration_get_realmsTable(cfg)[0], CLIENTREALM_MODE_UNKNOWN);
        }
      }
      else if ((strcmp(helpbuf1, "U") == 0) || (strcmp(helpbuf1, "reverseudp") == 0)) {
        if (ClientRealm_get_clientMode(ClientConfiguration_get_realmsTable(cfg)[0]) == CLIENTREALM_MODE_TCP) {
          ClientRealm_set_clientMode(ClientConfiguration_get_realmsTable(cfg)[0], CLIENTREALM_MODE_REVERSE);
        }
        else {
          ClientRealm_set_clientMode(ClientConfiguration_get_realmsTable(cfg)[0], CLIENTREALM_MODE_UNKNOWN);
        }
      }
      else if ((strcmp(helpbuf1, "r") == 0) || (strcmp(helpbuf1, "remoteadmin") == 0)) {
        if (ClientRealm_get_clientMode(ClientConfiguration_get_realmsTable(cfg)[0]) == CLIENTREALM_MODE_TCP) {
          ClientRealm_set_clientMode(ClientConfiguration_get_realmsTable(cfg)[0], CLIENTREALM_MODE_REMOTE);
        }
        else {
          ClientRealm_set_clientMode(ClientConfiguration_get_realmsTable(cfg)[0], CLIENTREALM_MODE_UNKNOWN);
        }
      }
#ifdef AF_INET6
      else if (strcmp(helpbuf1, "ipv4")==0) {
        if (TYPE_IS_UNSPEC(ClientRealm_get_realmType(
                ClientConfiguration_get_realmsTable(cfg)[0]))) {
          temp = ClientRealm_get_realmType(ClientConfiguration_get_realmsTable(cfg)[0]);
          TYPE_SET_IPV4(temp);
          ClientRealm_set_realmType(ClientConfiguration_get_realmsTable(cfg)[0], temp);
        }
        else {
          return cfg;
        }
      }
      else if (strcmp(helpbuf1, "ipv6")==0) {
        if (TYPE_IS_UNSPEC(ClientRealm_get_realmType(
                ClientConfiguration_get_realmsTable(cfg)[0]))) {
          temp = ClientRealm_get_realmType(ClientConfiguration_get_realmsTable(cfg)[0]);
          TYPE_SET_IPV6(temp);
          ClientRealm_set_realmType(ClientConfiguration_get_realmsTable(cfg)[0], temp);
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
      if ((strcmp(helpbuf1, "k") == 0) || (strcmp(helpbuf1, "keyfile") == 0)) {
        ClientConfiguration_set_keysFile(cfg, helpbuf2);
      }
      else if ((strcmp(helpbuf1, "c") == 0) || (strcmp(helpbuf1, "certificate") == 0) || (strcmp(helpbuf1, "cerfile") == 0)) {
        ClientConfiguration_set_certificateFile(cfg, helpbuf2);
      }
      else if ((strcmp(helpbuf1, "s") == 0) || (strcmp(helpbuf1, "storefile") == 0)) {
        ClientConfiguration_set_storeFile(cfg, helpbuf2);
      }
      else if ((strcmp(helpbuf1, "o") == 0) || (strcmp(helpbuf1, "log") == 0)) {
        tmpbuf = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(tmpbuf, helpbuf2);
        addlogtarget(tmpbuf);
      }
      else if ((strcmp(helpbuf1, "D") == 0) || (strcmp(helpbuf1, "dateformat") == 0)) {
        ClientConfiguration_set_dateFormat(cfg, helpbuf2);
      }
      else if ((strcmp(helpbuf1, "n") == 0) || (strcmp(helpbuf1, "servername") == 0)) {
        ClientRealm_set_serverName(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if ((strcmp(helpbuf1, "m") == 0) || (strcmp(helpbuf1, "manageport") == 0)) {
        ClientRealm_set_managePort(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if ((strcmp(helpbuf1, "d") == 0) || (strcmp(helpbuf1, "hostname") == 0)) {
        ClientRealm_set_hostName(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if ((strcmp(helpbuf1, "p") == 0) || (strcmp(helpbuf1, "portnum") == 0)) {
        PortList_insert_back(ClientRealm_get_destinationPorts(ClientConfiguration_get_realmsTable(cfg)[0]),
            PortListNode_new(helpbuf2));
      }
      else if (strcmp(helpbuf1, "localname") == 0) {
        ClientRealm_set_localName(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if (strcmp(helpbuf1, "localport") == 0) {
        ClientRealm_set_localPort(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if (strcmp(helpbuf1, "localdesname") == 0) {
        ClientRealm_set_localDestinationName(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if ((strcmp(helpbuf1, "i") == 0) || (strcmp(helpbuf1, "id") == 0)) {
        ClientRealm_set_realmId(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if (strcmp(helpbuf1, "pass") == 0) {
        n = strlen(helpbuf2);
        memset(pass, 0, 4);
        for (i = 0; i < n; ++i) {
          pass[i%4] += helpbuf2[i];
        }
        ClientRealm_set_password(ClientConfiguration_get_realmsTable(cfg)[0], pass);
      }
      else if ((strcmp(helpbuf1, "K") == 0) || (strcmp(helpbuf1, "keep-alive") == 0)) {
        ClientRealm_set_sKeepAliveTimeout(ClientConfiguration_get_realmsTable(cfg)[0], helpbuf2);
      }
      else if ((strcmp(helpbuf1, "A") == 0) || (strcmp(helpbuf1, "ar-tries") == 0)) {
        ArOptions_set_s_arTries(ClientRealm_get_arOptions(ClientConfiguration_get_realmsTable(cfg)[0]),
            helpbuf2);
      }
      else if ((strcmp(helpbuf1, "T") == 0) || (strcmp(helpbuf1, "ar-delay") == 0)) {
        ArOptions_set_s_arDelay(ClientRealm_get_arOptions(ClientConfiguration_get_realmsTable(cfg)[0]),
            helpbuf2);
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

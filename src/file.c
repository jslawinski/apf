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

#include "file.h"
#include "activefor.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

int
parse_line(char* buff, char* tab1, char* tab2)
{
  int state, i, j, lastDot;
  state = i = j = 0;
  lastDot = -1;
  while (buff[i] != 0) {
    if (buff[i] == '#') {
      if ((i > 0) && (buff[i-1] == '\\')) {
        --j;
      }
      else {
        break;
      }
    }
    switch (state) {
      case 0: { /* before option name */
                if (!isspace(buff[i])) {
                  tab1[j] = buff[i];
                  j = 1;
                  state = 1;
                }
                break;
              }
      case 1: { /* option */
                if (isspace(buff[i])) {
                  tab1[j] = 0;
                  state = 2;
                  j = 0;
                }
                else {
                  tab1[j] = buff[i];
                  ++j;
                }
                break;
              }
      case 2: { /* before option value */
                if (!isspace(buff[i])) {
                  if (buff[i] != '.') {
                    tab2[j] = buff[i];
                    j = 1;
                  }
                  state = 3;
                }
                break;
              }
      case 3: { /* option value */
                if (buff[i] == '.') {
                  lastDot = j;
                }
                else if (!isspace(buff[i])) {
                  lastDot = -1;
                }
                else if (lastDot == -1) {
                  lastDot = j;
                }
                tab2[j] = buff[i];
                ++j;
                break;
              }
    }
    ++i;
  }
  if (lastDot != -1) {
    tab2[lastDot] = 0;
  }
  if (state == 3) {
    return 2;
  }
  if (state == 0) {
    return 0;
  }
  return 1;
}

ConfigurationT
parsefile(char* name, int* status)
{
  static ConfigurationT cfg;
  FILE* file = NULL;
  int state, i, n, listencount, managecount;
  char buff[256];
  char helpbuf1[256];
  char helpbuf2[256];

  *status = 1;

  memset(buff, 0, 256);
	
  cfg.certif = NULL;
  cfg.keys = NULL;
  cfg.size = 0;
  cfg.realmtable = NULL;
  cfg.logging = 0;
  cfg.socklogging = 0;
  cfg.logfnam = NULL;
  cfg.logsport = NULL;
  cfg.dateformat = NULL;

  state = F_UNKNOWN;
	
  file = fopen(name, "r");
  if (file == NULL) {
    return cfg;
  }

  while (fgets(buff, 256, file) != NULL) { /* first loop - counting realm */
    helpbuf1[0] = 0;
    parse_line(buff, helpbuf1, helpbuf2);
    if (strcmp(helpbuf1, "realm")==0) {
      ++cfg.size;
    }
  }
  rewind(file);
	
  cfg.realmtable = calloc(cfg.size, sizeof(RealmT));
  for (i=0; i<cfg.size; ++i) {
    cfg.realmtable[i].pass[0] = 1;
    cfg.realmtable[i].pass[1] = 2;
    cfg.realmtable[i].pass[2] = 3;
    cfg.realmtable[i].pass[3] = 4;
  }
  cfg.size = 0;
  *status = 0;

  listencount = managecount = 0;
  
  
  while (fgets(buff, 256, file) != NULL) { /* second loop - counting listen */
    (*status)++;
    state = parse_line(buff, helpbuf1, helpbuf2);
    if (state) {
      if (strcmp(helpbuf1, "realm")==0) {
        ++cfg.size;
        if (listencount != managecount) {
          return cfg;
        }
        listencount = managecount = 0;
      }
      else if (strcmp(helpbuf1, "listen")==0) {
        if (cfg.size == 0) {
          return cfg;
        }
        ++cfg.realmtable[cfg.size-1].usrclinum;
        ++listencount;
      }
      else if (strcmp(helpbuf1, "manage")==0) {
        if (cfg.size == 0) {
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

  for (i=0; i<cfg.size; ++i) {
    cfg.realmtable[i].usrclitable = calloc(cfg.realmtable[i].usrclinum, sizeof(UsrCliT));
  }
  
  cfg.size = 0;
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
        ++cfg.size;
        TYPE_SET_SSL(cfg.realmtable[cfg.size-1].type);
        TYPE_SET_ZLIB(cfg.realmtable[cfg.size-1].type);
        listencount = managecount = 0;
      }
      else if (cfg.size == 0) {
        return cfg;
      }
      else if (strcmp(helpbuf1, "nossl")==0) {
        TYPE_UNSET_SSL(cfg.realmtable[cfg.size-1].type);
      }
      else if (strcmp(helpbuf1, "nozlib")==0) {
        TYPE_UNSET_ZLIB(cfg.realmtable[cfg.size-1].type);
      }
      else if (strcmp(helpbuf1, "baseport")==0) {
        cfg.realmtable[cfg.size-1].baseport = 1;
      }
      else if (strcmp(helpbuf1, "dnslookups")==0) {
        cfg.realmtable[cfg.size-1].dnslookups = 1;
      }
      else if (strcmp(helpbuf1, "ipv4")==0) {
        if (TYPE_IS_UNSPEC(cfg.realmtable[cfg.size-1].type)) {
          TYPE_SET_IPV4(cfg.realmtable[cfg.size-1].type);
        }
        else {
          return cfg;
        }
      }
      else if (strcmp(helpbuf1, "ipv6")==0) {
        if (TYPE_IS_UNSPEC(cfg.realmtable[cfg.size-1].type)) {
          TYPE_SET_IPV6(cfg.realmtable[cfg.size-1].type);
        }
        else {
          return cfg;
        }
      }
      else {
        return cfg;
      }
    }
    else if (state == 2) {
      if (strcmp(helpbuf1, "realm")==0) {
        ++cfg.size;
        TYPE_SET_SSL(cfg.realmtable[cfg.size-1].type);
        TYPE_SET_ZLIB(cfg.realmtable[cfg.size-1].type);
        listencount = managecount = 0;
        cfg.realmtable[cfg.size-1].realmname = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].realmname, helpbuf2);
      }
      else if (strcmp(helpbuf1, "certificate")==0) {
        cfg.certif = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.certif, helpbuf2);
      }
      else if (strcmp(helpbuf1, "key")==0) {
        cfg.keys = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.keys, helpbuf2);
      }
      else if (strcmp(helpbuf1, "heavylog")==0) {
        if (cfg.logging) {
          return cfg;
        }
        cfg.logging = 3;
        cfg.logfnam = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.logfnam, helpbuf2);
      }
      else if (strcmp(helpbuf1, "lightlog")==0) {
        if (cfg.logging) {
          return cfg;
        }
        cfg.logging = 1;
        cfg.logfnam = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.logfnam, helpbuf2);
      }
      else if (strcmp(helpbuf1, "heavysocklog")==0) {
        if (cfg.socklogging) {
          return cfg;
        }
        cfg.socklogging = 3;
        cfg.logsport = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.logsport, helpbuf2);
      }
      else if (strcmp(helpbuf1, "lightsocklog")==0) {
        if (cfg.socklogging) {
          return cfg;
        }
        cfg.socklogging = 1;
        cfg.logsport = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.logsport, helpbuf2);
      }
      else if (strcmp(helpbuf1, "dateformat")==0) {
        cfg.dateformat = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.dateformat, helpbuf2);
      }
      else if (cfg.size == 0) {
        return cfg;
      }
      else if (strcmp(helpbuf1, "hostname")==0) {
        cfg.realmtable[cfg.size-1].hostname = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].hostname, helpbuf2);
      }
      else if (strcmp(helpbuf1, "listen")==0) {
        cfg.realmtable[cfg.size-1].usrclitable[listencount].lisportnum=calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].usrclitable[listencount].lisportnum, helpbuf2);
        ++listencount;
      }
      else if (strcmp(helpbuf1, "pass")==0) {
        n = strlen(helpbuf2);
        memset(cfg.realmtable[cfg.size-1].pass, 0, 4);
        for (i = 0; i < n; ++i) {
          cfg.realmtable[cfg.size-1].pass[i%4] += helpbuf2[i];
        }
      }
      else if (strcmp(helpbuf1, "manage")==0) {
        cfg.realmtable[cfg.size-1].usrclitable[managecount].manportnum=calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].usrclitable[managecount].manportnum, helpbuf2);
        ++managecount;
      }
      else if (strcmp(helpbuf1, "users")==0) {
        cfg.realmtable[cfg.size-1].users = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].users, helpbuf2);
      }
      else if (strcmp(helpbuf1, "timeout")==0) {
        cfg.realmtable[cfg.size-1].timeout = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].timeout, helpbuf2);
      }
      else if (strcmp(helpbuf1, "clients")==0) {
        cfg.realmtable[cfg.size-1].clients = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].clients, helpbuf2);
      }
      else if (strcmp(helpbuf1, "raclients")==0) {
        cfg.realmtable[cfg.size-1].raclients = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].raclients, helpbuf2);
      }
      else if (strcmp(helpbuf1, "usrpcli")==0) {
        cfg.realmtable[cfg.size-1].usrpcli = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].usrpcli, helpbuf2);
      }
      else if (strcmp(helpbuf1, "climode")==0) {
        cfg.realmtable[cfg.size-1].clim = calloc(strlen(helpbuf2)+1, sizeof(char));
        strcpy(cfg.realmtable[cfg.size-1].clim, helpbuf2);
      }
      else if (strcmp(helpbuf1, "proto")==0) {
        if (TYPE_IS_SET(cfg.realmtable[cfg.size-1].type)) {
          return cfg;
        }
        if (strcmp(helpbuf2, "tcp")==0) {
          TYPE_SET_TCP(cfg.realmtable[cfg.size-1].type);
        }
        else if (strcmp(helpbuf2, "udp")==0) {
          TYPE_SET_UDP(cfg.realmtable[cfg.size-1].type);
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


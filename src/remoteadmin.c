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

#include "remoteadmin.h"

static char newmessage;

static int
parse_cmd(unsigned char* buff, int* ret)
{
  int i, j, state;
  char cmd[31];

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
  return 0;
}

static void
send_adm_message(char type, clifd master, unsigned char* buff, unsigned char st)
{
  int n;
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
  send_message(type, master, buff, n+5);
}

static void
add_to_message(unsigned char* buff, const char* format, ...)
{
  va_list ap;
  int n;
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

static void
add_uptime_to_message(unsigned char* buff, char* info, time_t period)
{
  int hours, minutes, seconds;

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

int
serve_admin(ConfigurationT* config, int realm, int client, unsigned char* buff)
{
  int length, n, i, j, ret;
  time_t now, tmp;
  char type = config->realmtable[realm].type | TYPE_SSL | TYPE_ZLIB;
  clifd master = config->realmtable[realm].raclitable[client].cliconn;
  
  length = buff[3];
  length = length << 8;
  length += buff[4]; /* this is length of message */
  
  time(&now);
  
  switch (buff[1]) {
    case AF_RA_CMD: {
                      n = get_message(type, master, buff, length);
                      buff[n] = 0;
                      aflog(2, "   realm[%s]: admin: message length = %d [%s]",
                          get_realmname(config, realm), n, buff);
                      switch (parse_cmd(buff, &ret)) {
                        case 1: { /* help */
                                  add_to_message(buff, AF_VER("AFSERVER"));
                                  add_to_message(buff, "\nValid commands are:");
                                  add_to_message(buff, "  help              display help");
                                  add_to_message(buff, "  lcmd              lists available commands");
                                  add_to_message(buff, "  info              prints info about server");
                                  add_to_message(buff, "  rshow             display realms");
                                  add_to_message(buff, "  cshow X           display clients in X realm");
                                  add_to_message(buff, "  ushow X           display users in X realm");
                                  add_to_message(buff, "  quit              quit connection");
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
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 3: { /* info */
                                  add_to_message(buff, AF_VER("Version:"));
                                  add_to_message(buff, "Realms: %d", config->size);
                                  add_to_message(buff, "Certificate: %s", config->certif);
                                  add_to_message(buff, "Key: %s", config->keys);
                                  if (config->logging) {
                                  add_to_message(buff, "logfile: %s (verbosity:%d)",
                                      config->logfnam, config->logging);
                                  }
                                  else {
                                  add_to_message(buff, "no logfile");
                                  }
                                  if (config->socklogging) {
                                  add_to_message(buff, "logsocket: %s (verbosity:%d)",
                                      config->logsport, config->socklogging);
                                  }
                                  else {
                                  add_to_message(buff, "no logsocket");
                                  }
                                  tmp = now - config->starttime;
                                  add_uptime_to_message(buff, "Uptime", tmp);
                                  add_to_message(buff, "Cg: %ld B", getcg());
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 4: { /* rshow */
                                  for (i = 0; i < config->size; ++i) {
                                    add_to_message(buff, "\nRealm[%s]:", get_realmname(config, i));
                                    add_to_message(buff, "hostname: %s", config->realmtable[i].hostname);
                                    add_to_message(buff, "users: %d (max: %d)",
                                        config->realmtable[i].usercon, config->realmtable[i].usernum);
                                    add_to_message(buff, "clients: %d (max: %d)",
                                        config->realmtable[i].clicon-config->realmtable[i].raclicon,
                                        config->realmtable[i].clinum);
                                    add_to_message(buff, "raclients: %d (max: %d)",
                                        config->realmtable[i].raclicon, config->realmtable[i].raclinum);
                                    add_to_message(buff, "users per client: %s", config->realmtable[i].usrpcli);
                                    add_to_message(buff, "user-client pairs: %d",
                                        config->realmtable[i].usrclinum);
                                    for (j = 0; j < config->realmtable[i].usrclinum; ++j) {
                                      add_to_message(buff, " pair[%d]: listenport: %s, manageport: %s", j,
                                          config->realmtable[i].usrclitable[j].lisportnum,
                                          config->realmtable[i].usrclitable[j].manportnum);
                                    }
                                    add_to_message(buff, "climode: %s", config->realmtable[i].clim);
                                    add_to_message(buff, "timeout: %s", config->realmtable[i].timeout);
                                    add_to_message(buff, "baseport: %s", config->realmtable[i].baseport ?
                                        "yes" : "no");
                                    add_to_message(buff, "ssl: %s, zlib: %s, mode: %s",
                                        (TYPE_IS_SSL(config->realmtable[i].type))?"yes":"no",
                                        (TYPE_IS_ZLIB(config->realmtable[i].type))?"yes":"no",
                                        (TYPE_IS_TCP(config->realmtable[i].type))?"tcp":"udp");
                                  }
                                  send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                  break;
                                }
                        case 5: { /* cshow*/
                                  n = get_realmnumber(config, (char*) &buff[ret]);
                                  if ((n >= 0) && (n < config->size)) {
                                    for (i = 0; i < config->realmtable[n].clinum; ++i) {
                                      if (config->realmtable[n].clitable[i].ready) {
                                        add_to_message(buff, "\nClient[%s]:",
                                            get_clientname(&(config->realmtable[n]), i));
                                        switch (config->realmtable[n].clitable[i].ready) {
                                          case 1: {
                                                    add_to_message(buff, "state: ssl handshake");
                                                    break;
                                                  }
                                          case 2: {
                                                    add_to_message(buff, "state: authorization");
                                                    break;
                                                  }
                                          case 3: {
                                                    add_to_message(buff, "state: running");
                                                    break;
                                                  }
                                          default: {
                                                    add_to_message(buff, "state: unknown");
                                                   }
                                        }
                                        add_to_message(buff, "users: %d (max: %d)",
                                            config->realmtable[n].clitable[i].usercon,
                                            config->realmtable[n].clitable[i].usernum);
                                        add_to_message(buff, "user-client pair: %d",
                                            config->realmtable[n].clitable[i].whatusrcli); 
                                        tmp = now - config->realmtable[n].clitable[i].connecttime;
                                        add_uptime_to_message(buff, "Connection time", tmp);
                                        add_to_message(buff, "Id: %s",
                                            (config->realmtable[n].clitable[i].clientid == NULL)?"":
                                            config->realmtable[n].clitable[i].clientid);
                                        add_to_message(buff, "IP: %s, port: %s",
                                            config->realmtable[n].clitable[i].namebuf,
                                            config->realmtable[n].clitable[i].portbuf);
                                      }
                                    }
                                    send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                    break;
                                  }
                                  add_to_message(buff, "Wrong realm name");
                                  send_adm_message(type, master, buff, AF_RA_FAILED);
                                  break;
                                }
                        case 6: { /* ushow */
                                  n = get_realmnumber(config, (char*) &buff[ret]);
                                  if ((n >= 0) && (n < config->size)) {
                                    for (i = 0; i < config->realmtable[n].usernum; ++i) {
                                      if (config->realmtable[n].contable[i].state != S_STATE_CLEAR) {
                                        add_to_message(buff, "\nUser[%d]:",
                                            get_username(&(config->realmtable[n]), i));
                                        switch (config->realmtable[n].contable[i].state) {
                                          case S_STATE_CLOSING: {
                                                    add_to_message(buff, "state: closing");
                                                    break;
                                                  }
                                          case S_STATE_OPENING: {
                                                    add_to_message(buff, "state: opening");
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
                                            get_clientname(&(config->realmtable[n]),
                                              config->realmtable[n].contable[i].whatcli));
                                        tmp = now - config->realmtable[n].contable[i].connecttime;
                                        add_uptime_to_message(buff, "Connection time", tmp);
                                        add_to_message(buff, "IP: %s, port: %s",
                                            config->realmtable[n].contable[i].namebuf,
                                            config->realmtable[n].contable[i].portbuf);
                                      }
                                    }
                                    send_adm_message(type, master, buff, AF_RA_STATUS_OK);
                                    break;
                                  }
                                  add_to_message(buff, "Wrong realm name");
                                  send_adm_message(type, master, buff, AF_RA_FAILED);
                                  break;
                                }
                        case 7: { /* quit */
                                  aflog(1, "  realm[%s]: Client[%s] (ra): commfd: CLOSED",
                                      get_realmname(config, realm),
                                      get_raclientname(&(config->realmtable[realm]), client));
                                  send_adm_message(type, master, buff, AF_RA_KICKED);
                                  return 1;
                                }
                        default: {
                                  aflog(2, "   realm[%s]: admin: cmd ignored", get_realmname(config, realm));
                                  send_adm_message(type, master, buff, AF_RA_UNDEFINED);
                                 }
                      }
                      break;
                    }
    case AF_RA_REPEAT: {
                         break;
                       }
    default: {
               aflog(1, "Unrecognized message from remote admin --> closing");
               return 1;
             }
  }
  return 0;
}

int
client_admin(char type, clifd master, unsigned char* buff, int connectfd, char* id)
{
  fd_set rset, allset;
  int maxfdp1, n, length, infd;
  FILE *outfp, *infp;

  buff[0] = AF_S_ADMIN_LOGIN;
  send_message(type, master, buff, 5);
  buff[0] = 0;
  get_message(type, master, buff, -5);

  if ( buff[0] == 0 ) {
    aflog(0, "Wrong password");
    return 1;
  }
  if ( buff[0] == AF_S_CANT_OPEN ) {
    aflog(0, "Server is full");
    return 1;
  }
  if ( buff[0] != AF_S_ADMIN_LOGIN ) {
    aflog(0, "Incompatible server type or server full");
    return 1;
  }
 
  aflog(1, "CLIENT STARTED mode: remote administration");
  
  if (connectfd > 0) {
    outfp = fdopen(connectfd, "w");
    if (outfp == NULL) {
      aflog(0, "Error in opening file descriptor for writing");
      return 1;
    }
    infd = connectfd;
  }
  else {
    infd = STDIN_FILENO;
    outfp = stdout;
  }
  infp = fdopen(infd, "r");
  if (infp == NULL) {
    aflog(0, "Error in opening file descriptor for reading");
    return 1;
  }
  
  length = buff[3];
  length = length << 8;
  length += buff[4]; /* this is length of message */
  n = get_message(type, master, buff, length);
  buff[n] = 0;
  fprintf(outfp, "%s\n", (char*) buff);
  fflush(outfp);
  
  FD_ZERO(&allset);

  FD_SET(master.commfd, &allset);
  FD_SET(infd, &allset);
  
  maxfdp1 = (infd > master.commfd) ? infd+1: master.commfd+1;

  if (id != NULL) {
    buff[0] = AF_S_LOGIN;
    buff[1] = buff[2] = 0;
    n = strlen(id);
    memcpy(&buff[5], id, n);
    buff[3] = n >> 8; /* high bits of message length */
    buff[4] = n;    /* low bits of message length */
    send_message(type, master, buff, n+5);
    aflog(1, "ID SENT: %s", id);
  }
  
  while (1) {
    rset = allset;
    select(maxfdp1, &rset, NULL, NULL, NULL);

    if (FD_ISSET(master.commfd, &rset)) {
      aflog(3, " masterfd: FD_ISSET");
      n = get_message(type, master, buff, 5);
      if (n != 5) {
        aflog(2, "  FATAL ERROR! (%d)", n);
        if (n == -1) {
          if (TYPE_IS_SSL(type)) {
            get_ssl_error(&master, "FE", n);
            continue; /* what happened? */
          }
        }
        if (n != 0)
          return 1;
      } 
      if (n == 0) { /* server quits -> we do the same... */
        aflog(0, "  SERVER: premature quit --> exiting...");
        return 1;
      }
      if (buff[0] == AF_S_CLOSING) {
        aflog(0, "  SERVER: CLOSED -> exiting... cg: %ld bytes", getcg());
        return 0;
      }
      if (buff[0] != AF_S_ADMIN_CMD) {
        aflog(0, "  SERVER: wrong message --> exiting");
        return 1;
      }
      length = buff[3];
      length = length << 8;
      length += buff[4]; /* this is length of message */
      
      switch (buff[1]) {
        case AF_RA_STATUS_OK: {
                      aflog(1, "  SERVER: cmd successful");
                              }
        case AF_RA_FAILED: {
                      if (buff[1] == AF_RA_FAILED) {
                        aflog(1, "  SERVER: cmd failed");
                      }
                           }
        case AF_RA_UNDEFINED: {
                      if (buff[1] == AF_RA_UNDEFINED) {
                        aflog(1, "  SERVER: unknown cmd");
                      }
                      n = get_message(type, master, buff, length);
                      buff[n] = 0;
                      fprintf(outfp, "%s", (char*) buff);
                      fflush(outfp);
                             break;
                           }
        case AF_RA_KICKED: {
                   aflog(0, "  SERVER: kicked us -> exiting... cg: %ld bytes", getcg());
                   return 1;
                             break;
                           }
        default: {
                   aflog(0, "  SERVER: unrecognized message -> exiting... cg: %ld bytes", getcg());
                   return 1;
                 }
      }
    }

    if (FD_ISSET(infd, &rset)) {
      aflog(3, " infd: FD_ISSET");
      if (fgets((char*) &buff[5], 8091, infp) == NULL) { /* client quits --> exiting */
        aflog(0, "  CLIENT CLOSED cg: %ld bytes", getcg());
        return 0;
      }
      n = strlen((char*) &buff[5]);
      if ((n > 0) && (buff[n+4] == '\n')) {
        --n;
      }
      buff[0] = AF_S_ADMIN_CMD;
      buff[1] = AF_RA_CMD;
      buff[2] = AF_RA_UNDEFINED;
      buff[3] = n >> 8; /* high bits of message length */
      buff[4] = n;    /* low bits of message length */
      send_message(type, master, buff, n+5);
    }
  }
}

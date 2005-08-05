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

#include <config.h>

#include "client_remoteadmin.h"

int
client_admin(char type, SslFd* master, unsigned char* buff, int connectfd, char* id)
{
  fd_set rset, allset;
  int maxfdp1, n, length, infd;
  FILE *outfp, *infp;

  buff[0] = AF_S_ADMIN_LOGIN;
  SslFd_send_message(type, master, buff, 5);
  buff[0] = 0;
  SslFd_get_message(type, master, buff, -5);

  if ( buff[0] == 0 ) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Wrong password");
    return 1;
  }
  if ( buff[0] == AF_S_CANT_OPEN ) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Server is full");
    return 1;
  }
  if ( buff[0] != AF_S_ADMIN_LOGIN ) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Incompatible server type or server full");
    return 1;
  }
 
  aflog(LOG_T_MAIN, LOG_I_INFO,
      "CLIENT STARTED mode: remote administration");
  
  if (connectfd > 0) {
    outfp = fdopen(connectfd, "w");
    if (outfp == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Error in opening file descriptor for writing");
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
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Error in opening file descriptor for reading");
    return 1;
  }
  
  length = buff[3];
  length = length << 8;
  length += buff[4]; /* this is length of message */
  n = SslFd_get_message(type, master, buff, length);
  buff[n] = 0;
  fprintf(outfp, "%s\n", (char*) buff);
  fflush(outfp);
  
  FD_ZERO(&allset);

  FD_SET(SslFd_get_fd(master), &allset);
  FD_SET(infd, &allset);
  
  maxfdp1 = (infd > SslFd_get_fd(master)) ? infd + 1 : SslFd_get_fd(master) + 1;

  if (id != NULL) {
    buff[0] = AF_S_LOGIN;
    buff[1] = buff[2] = 0;
    n = strlen(id);
    memcpy(&buff[5], id, n);
    buff[3] = n >> 8; /* high bits of message length */
    buff[4] = n;    /* low bits of message length */
    SslFd_send_message(type, master, buff, n+5);
    aflog(LOG_T_MANAGE, LOG_I_INFO,
        "ID SENT: %s", id);
  }
  
  while (1) {
    rset = allset;
    select(maxfdp1, &rset, NULL, NULL, NULL);

    if (FD_ISSET(SslFd_get_fd(master), &rset)) {
      aflog(LOG_T_MANAGE, LOG_I_DEBUG,
          "masterfd: FD_ISSET");
      n = SslFd_get_message(type, master, buff, 5);
      if (n != 5) {
        aflog(LOG_T_MANAGE, LOG_I_ERR,
            "FATAL ERROR! (%d)", n);
        if (n == -1) {
          if (TYPE_IS_SSL(type)) {
            get_ssl_error(master, "FE", n);
            continue; /* what happened? */
          }
        }
        if (n != 0)
          return 1;
      } 
      if (n == 0) { /* server quits -> we do the same... */
        aflog(LOG_T_MANAGE, LOG_I_CRIT,
            "SERVER: premature quit --> exiting...");
        return 1;
      }
      if (buff[0] == AF_S_CLOSING) {
        aflog(LOG_T_MANAGE, LOG_I_CRIT,
            "SERVER: CLOSED -> exiting... cg: %ld bytes", getcg());
        return 0;
      }
      if (buff[0] != AF_S_ADMIN_CMD) {
        aflog(LOG_T_MANAGE, LOG_I_CRIT,
            "SERVER: wrong message --> exiting");
        return 1;
      }
      length = buff[3];
      length = length << 8;
      length += buff[4]; /* this is length of message */
      
      switch (buff[1]) {
        case AF_RA_STATUS_OK: {
                      aflog(LOG_T_MANAGE, LOG_I_INFO,
                          "SERVER: cmd successful");
                              }
        case AF_RA_FAILED: {
                      if (buff[1] == AF_RA_FAILED) {
                        aflog(LOG_T_MANAGE, LOG_I_INFO,
                            "SERVER: cmd failed");
                      }
                           }
        case AF_RA_UNDEFINED: {
                      if (buff[1] == AF_RA_UNDEFINED) {
                        aflog(LOG_T_MANAGE, LOG_I_WARNING,
                            "SERVER: unknown cmd");
                      }
                      n = SslFd_get_message(type, master, buff, length);
                      buff[n] = 0;
                      fprintf(outfp, "%s", (char*) buff);
                      fflush(outfp);
                             break;
                           }
        case AF_RA_KICKED: {
                   aflog(LOG_T_MANAGE, LOG_I_ERR,
                       "SERVER: kicked us -> exiting... cg: %ld bytes", getcg());
                   return 1;
                             break;
                           }
        default: {
                   aflog(LOG_T_MANAGE, LOG_I_ERR,
                       "SERVER: unrecognized message -> exiting... cg: %ld bytes", getcg());
                   return 1;
                 }
      }
    }

    if (FD_ISSET(infd, &rset)) {
      aflog(LOG_T_MANAGE, LOG_I_DEBUG,
          "infd: FD_ISSET");
      if (fgets((char*) &buff[5], 8091, infp) == NULL) { /* client quits --> exiting */
        aflog(LOG_T_MANAGE, LOG_I_NOTICE,
            "CLIENT CLOSED cg: %ld bytes", getcg());
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
      SslFd_send_message(type, master, buff, n+5);
    }
  }
}

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

#include "client_reverse_udp.h"

#include <stdlib.h>

int
initialize_client_reverse_udp(ClientRealm* cr)
{
  int tmp;
  int wanttoexit = (ArOptions_get_arStart(ClientRealm_get_arOptions(cr)) == AR_OPTION_ENABLED) ? 0 : 1;
  ClientRealm_set_usersLimit(cr, 1);
  if (ip_connect(&tmp, ClientRealm_get_serverName(cr),
        ClientRealm_get_managePort(cr),
        ClientRealm_get_ipFamily(cr), NULL, NULL)) {
#ifdef AF_INET6
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "tcp_connect_%s error for %s, %s",
        (ClientRealm_get_ipFamily(cr) & 0x02) ?
          "ipv4" : (ClientRealm_get_ipFamily(cr) & 0x04) ?
            "ipv6":"unspec", ClientRealm_get_serverName(cr), ClientRealm_get_managePort(cr));
#else
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "tcp_connect error for %s, %s", ClientRealm_get_serverName(cr), ClientRealm_get_managePort(cr));
#endif
    if (wanttoexit) {
      exit(1);
    }
    else {
      return 1;
    }

  }
  SslFd_set_fd(ClientRealm_get_masterSslFd(cr), tmp);
  SslFd_set_ssl(ClientRealm_get_masterSslFd(cr), NULL);
  return 0;
}

void
client_reverse_udp(ClientRealm* cr, unsigned char* buff, int buflength)
{
  socklen_t len, addrlen;
  int maxfdp1, temp, notsent, n, length;
  struct sockaddr* cliaddr;
  fd_set rset, allset;

  if (ip_listen(&temp, ClientRealm_get_hostName(cr),
        ClientRealm_get_destinationPort(cr), &addrlen,
        ClientRealm_get_ipFamily(cr) & 0xfe)) {
#ifdef AF_INET6
    aflog(LOG_T_INIT, LOG_I_DEBUG,
        "udp_listen_%s error for %s, %s",
        (ClientRealm_get_ipFamily(cr) & 0x02) ?
          "ipv4":(ClientRealm_get_ipFamily(cr) & 0x04) ?
            "ipv6":"unspec", ClientRealm_get_hostName(cr), ClientRealm_get_destinationPort(cr));
#else
    aflog(LOG_T_INIT, LOG_I_DEBUG,
        "udp_listen error for %s, %s", ClientRealm_get_hostName(cr), ClientRealm_get_destinationPort(cr));
#endif
    exit(1);
  }
  ConnectUser_set_connFd(ClientRealm_get_usersTable(cr)[0], temp);
  cliaddr = malloc(addrlen);
  FD_ZERO(&allset);

  FD_SET(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), &allset);
  maxfdp1 = SslFd_get_fd(ClientRealm_get_masterSslFd(cr)) + 1;
  maxfdp1 = (maxfdp1 > (ConnectUser_get_connFd(ClientRealm_get_usersTable(cr)[0]) + 1)) ?
    maxfdp1 : (ConnectUser_get_connFd(ClientRealm_get_usersTable(cr)[0]) + 1);
  FD_SET(ConnectUser_get_connFd(ClientRealm_get_usersTable(cr)[0]), &allset);
  aflog(LOG_T_CLIENT, LOG_I_INFO,
      "CLIENT STARTED mode: udp reverse");
  for ( ; ; ) {
    len = 4;
    if (getsockopt(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), SOL_SOCKET, SO_SNDBUF, &temp, &len) != -1) {
      if (temp != buflength) {
        buflength = temp;
        aflog(LOG_T_CLIENT, LOG_I_WARNING,
            "Send buffer size changed...");
      }
    }
    len = addrlen;
    rset = allset;
    aflog(LOG_T_MAIN, LOG_I_DEBUG,
        "select");
    select(maxfdp1, &rset, NULL, NULL, NULL);
    aflog(LOG_T_MAIN, LOG_I_DEBUG,
        "after select...");

    if (FD_ISSET(ConnectUser_get_connFd(ClientRealm_get_usersTable(cr)[0]), &rset)) { /* FD_ISSET   CONTABLE[0].CONNFD   RSET*/
      n = recvfrom(ConnectUser_get_connFd(ClientRealm_get_usersTable(cr)[0]), &buff[5], 8091, 0, cliaddr, &len);
#ifdef HAVE_LINUX_SOCKIOS_H
# ifdef SIOCOUTQ
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "SIOCOUTQ is defined");
      if (ioctl(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), SIOCOUTQ, &notsent)) {
        aflog(LOG_T_CLIENT, LOG_I_CRIT,
            "ioctl error -> exiting...");
        exit(1);
      }
      if (buflength <= notsent + n + 5) { /* when we can't do this */
        aflog(LOG_T_CLIENT, LOG_I_INFO,
            "drop: size:%d, buf:%d, w:%d/%d", n, buflength, notsent, buflength);
# else
      aflog(LOG_T_MAIN< LOG_I_DDEBUG,
          "TIOCOUTQ is defined");
      if (ioctl(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), TIOCOUTQ, &notsent)) {
        aflog(LOG_T_CLIENT, LOG_I_CRIT,
            "ioctl error -> exiting...");
        exit(1);
      }
      if (notsent <= n + 5) { /* when we can't do this */
        aflog(LOG_T_CLIENT, LOG_I_INFO,
            "drop: size:%d, buf:%d, w:%d/%d", n, buflength, buflength - notsent, buflength);
# endif
      }
      else {
#endif
        if (n > 0) {
#ifdef HAVE_LINUX_SOCKIOS_H
          aflog(LOG_T_CLIENT, LOG_I_INFO,
              "Sending %d bytes to service (w:%d/%d) (FROM:%s)", n,
# ifdef SIOCOUTQ
              notsent
# else
              buflength - notsent
# endif
              , buflength, sock_ntop(cliaddr, len, NULL, NULL, 0));
#else
          aflog(LOG_T_CLIENT, LOG_I_INFO,
              "Sending %d bytes to service (FROM:%s)", n, sock_ntop(cliaddr, len, NULL, NULL, 0));
#endif
          buff[0] = AF_S_MESSAGE;
          buff[1] = AF_S_LOGIN;
          buff[2] = AF_S_MESSAGE;
          buff[3] = n >> 8;
          buff[4] = n;
          writen(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), buff, n + 5);
        }
#ifdef HAVE_LINUX_SOCKIOS_H
      }
#endif
    } /* - FD_ISSET   CONTABLE[0].CONNFD   RSET */

    if (FD_ISSET(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), &rset)) { /* FD_ISSET   MASTER.COMMFD   RSET */
      n = readn(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), buff, 5);
      if (n == 5) {
        if ((buff[0] != AF_S_MESSAGE) || (buff[1] != AF_S_LOGIN) || (buff[2] != AF_S_MESSAGE)) {
          aflog(LOG_T_CLIENT, LOG_I_CRIT,
              "Incompatible server type (not udp?) or data corruption -> exiting...");
          exit(1);
        }
        length = buff[3];
        length = length << 8;
        length += buff[4]; /* this is length of message */
        n = readn(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), buff, length);
      }
      else {
        n = 0;
      }
      if (n == 0) { /* server quits -> we do the same... */
        aflog(LOG_T_CLIENT, LOG_I_CRIT,
            "premature quit of the server -> exiting...");
        exit(1);
      }
      aflog(LOG_T_CLIENT, LOG_I_INFO,
          "Sending %d bytes to user (TO:%s)", n, sock_ntop(cliaddr, addrlen, NULL, NULL, 0));
      sendto(ConnectUser_get_connFd(ClientRealm_get_usersTable(cr)[0]), buff, n, 0, cliaddr, addrlen);
    } /* - FD_ISSET   MASTER.COMMFD   RSET */
  }
  exit(0); /* we shouldn't get here */
}

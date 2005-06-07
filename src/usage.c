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

#include "usage.h"
#include "network.h"

#include <stdio.h>
#include <stdlib.h>

  void
server_short_usage(char* info)
{
  printf("\n%s\n\n\n", info);
  printf("Try `afserver --help' for more information.\n");
  
  exit(1);
}

  void
server_long_usage(char* info)
{
  printf("\n%s\n\n\n", info);
  printf(" Basic options:\n\n");
  printf("  -n, --hostname      - it's used when creating listening sockets\n");
  printf("                        (default: '')\n");
  printf("  -l, --listenport    - listening port number - users connect\n");
  printf("                        to it (default: 50127)\n");
  printf("  -m, --manageport    - manage port number - second part of the active\n");
  printf("                        port forwarder connects to it (default: 50126)\n");
  printf("  -V, --version       - display version number\n");
  printf("  -h, --help          - prints this help\n\n");
  printf(" Authorization:\n\n");
  printf("  --pass              - set the password used for client identification\n");
  printf("                        (default: no password)\n\n");
  printf(" Configuration:\n\n");
  printf("  -c, --cerfile       - the name of the file with certificate\n");
  printf("                        (default: cacert.pem)\n");
  printf("  -k, --keyfile       - the name of the file with RSA key (default: server.rsa)\n");
  printf("  -f, --cfgfile       - the name of the file with the configuration for the\n");
  printf("                        active forwarder (server)\n");
  printf("  -D, --dateformat    - format of the date printed in logs (see 'man strftime'\n");
  printf("                        for details) (default: %%d.%%m.%%Y %%H:%%M:%%S)\n\n");
  printf("  -t, --timeout       - the timeout value for the client's connection\n");
  printf("                        (default: 5)\n");
  printf("  -u, --users         - the amount of users allowed to use this server\n");
  printf("                        (default: 5)\n");
  printf("  -C, --clients       - the number of allowed clients to use this server\n");
  printf("                        (default: 1)\n");
  printf("  -r, --realm         - set the realm name (default: none)\n");
  printf("  -R, --raclients     - the number of allowed clients in remote administration\n");
  printf("                        mode to use this server (default: 1)\n");
  printf("  -U, --usrpcli       - the number of allowed users per client (default: $users)\n");
  printf("  -M, --climode       - strategy used to connect users with clients (default: 1)\n");
  printf("                      Available strategies:\n");
  printf("                        1. fill first client before go to next\n\n");
  printf("  -p, --proto         - type of server (tcp|udp) - what protocol it will be\n");
  printf("                        operating for (default: tcp)\n");
  printf("  -b, --baseport      - listenports are temporary and differ for each client\n");
  printf("  -a, --audit         - additional information about connections are logged\n");
  printf("  --nossl             - ssl is not used to transfer data (but it's still used\n");
  printf("                        to establish a connection) (default: ssl is used)\n");
  printf("  --nozlib            - zlib is not used to compress data (default: zlib is\n");
  printf("                        used)\n");
  printf("  --dnslookups        - try to obtain dns names of the computers rather than\n");
  printf("                        their numeric IP\n\n");
  printf(" Logging:\n\n");
  printf("  -o, --log           - log choosen information to file/socket\n");
  printf("  -v, --verbose       - to be verbose - program won't enter the daemon mode\n");
  printf("                        (use several times for greater effect)\n\n");
#ifdef AF_INET6
  printf(" IP family:\n\n");
  printf("  -4, --ipv4          - use ipv4 only\n");
  printf("  -6, --ipv6          - use ipv6 only\n\n");
#endif
#ifdef HAVE_LIBPTHREAD
  printf(" HTTP PROXY:\n\n");
  printf("  -P, --enableproxy   - enable http proxy mode\n\n");
#endif
  
  exit(0);
}

  void
client_short_usage(char* info)
{
  printf("\n%s\n\n\n", info);
  printf("Try `afclient --help' for more information.\n");
  
  exit(1);
}

void
client_long_usage(char* info)
{
  printf("\n%s\n\n\n", info);
  printf(" Basic options:\n\n");
  printf("  -n, --servername    - where the second part of the active\n");
  printf("                        port forwarder is running (required)\n");
  printf("  -m, --manageport    - manage port number - server must be\n");
  printf("                        listening on it (default: 50126)\n");
  printf("  -d, --hostname      - the name of this host/remote host - the final\n");
  printf("                        destination of the packets (default: the name\n");
  printf("                        returned by hostname function)\n");
  printf("  -p, --portnum       - the port we are forwarding connection to (required)\n");
  printf("  -V, --version       - display version number\n");
  printf("  -h, --help          - prints this help\n\n");
  printf(" Authorization:\n\n");
  printf("  -i, --id            - sends the id string to afserver\n");
  printf("  --pass              - set the password used for client identification\n");
  printf("                        (default: no password)\n\n");
  printf(" Configuration:\n\n");
  printf("  -k, --keyfile       - the name of the file with RSA key (default: client.rsa)\n");
  printf("  -D, --dateformat    - format of the date printed in logs (see 'man strftime'\n");
  printf("                        for details) (default: %%d.%%m.%%Y %%H:%%M:%%S)\n");
  printf("  -K, --keep-alive N  - send keepalive packets every N seconds\n");
  printf("                        (default: not send keepalive packets)\n");
  printf("  -A, --ar-tries N    - try N times to reconnect to afserver after\n");
  printf("                        its premature quit (default: unlimited)\n");
  printf("  -T, --ar-delay N    - wait N seconds between reconnect tries (default: 5)\n\n");
  printf(" Modes:\n\n");
  printf("  -u, --udpmode       - udp mode - client will use udp protocol to\n");
  printf("                        communicate with the hostname:portnum (-p)\n");
  printf("  -U, --reverseudp    - reverse udp forwarding. Udp packets will be forwarded\n");
  printf("                        from hostname:portnum (-p) to the server name:portnum\n");
  printf("                        (-m)\n");
  printf("  -r, --remoteadmin   - remote administration mode. (using '-p #port' will\n");
  printf("                        force afclient to use port rather than stdin-stdout)\n\n");
  printf(" Logging:\n\n");
  printf("  -o, --log           - log choosen information to file/socket\n");
  printf("  -v, --verbose       - to be verbose - program won't enter the daemon mode\n");
  printf("                        (use several times for greater effect)\n\n");
#ifdef AF_INET6
  printf(" IP family:\n\n");
  printf("  -4, --ipv4          - use ipv4 only\n");
  printf("  -6, --ipv6          - use ipv6 only\n\n");
#endif
#ifdef HAVE_LIBDL
  printf(" Modules:\n\n");
  printf("  -l, --load          - load a module for user's packets filtering\n");
  printf("  -L, --Load          - load a module for service's packets filtering\n\n");
#endif
#ifdef HAVE_LIBPTHREAD
  printf(" HTTP PROXY:\n\n");
  printf("  -P, --proxyname     - the name of the machine with proxy server\n");
  printf("  -X, --proxyport     - the port used by proxy server (default: 8080)\n\n");
#endif
  
  exit(0);
}

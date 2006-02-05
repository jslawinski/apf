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

#include "server_get.h"
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

/*
 * Function name: get_new_socket
 * Description: Returns new accepted socket.
 * Arguments: sockfd - the file descriptor of the listening socket
 *            type - the type of the listening socket
 *            addr - pointer to sockaddr structure
 *            addrlen - pointer to the length of the sockaddr structure
 *            tunneltype - the type of the connection
 * Returns: The new accepted socket.
 */

int
get_new_socket(int sockfd, char type, struct sockaddr *addr, socklen_t *addrlen, char* tunneltype)
{
  int tmp;
  int n, i;
  
  assert(addr != NULL);
  assert(addrlen != NULL);
  assert(tunneltype != NULL);
  
  switch (type) {
    case 0: {
              return accept(sockfd, addr, addrlen);
              break;
            }
    case 1: {
              i = 0;
              while (i < 4) {
                if ((n = read(sockfd, &tmp+i, 4-i)) != (4-i)) {
                  sleep(2);
                  if ((n > 0) && (n < 4)) {
                    i += n;
                    continue;
                  }
                  if ((n == -1) && (errno == EAGAIN)) {
                    continue;
                  }
                  return -1;
                }
                else {
                  break;
                }
              }
              i = 0;
              while (i < 1) {
                if ((n = read(sockfd, tunneltype+i, 1-i)) != (1-i)) {
                  if ((n == -1) && (errno == EAGAIN)) {
                    continue;
                  }
                  return -1;
                }
                else {
                  break;
                }
              }
              i = 0;
              while (i < 4) {
                if ((n = read(sockfd, addrlen+i, 4-i)) != (4-i)) {
                  if ((n > 0) && (n < 4)) {
                    i += n;
                    continue;
                  }
                  if ((n == -1) && (errno == EAGAIN)) {
                    continue;
                  }
                  return -1;
                }
                else {
                  break;
                }
              }
              i = 0;
              while (i < *addrlen) {
                if ((n = read(sockfd, addr+i, (*addrlen)-i)) != ((*addrlen)-i)) {
                  if ((n > 0) && (n < *addrlen)) {
                    i += n;
                    continue;
                  }
                  if ((n == -1) && (errno == EAGAIN)) {
                    continue;
                  }
                  return -1;
                }
                else {
                  break;
                }
              }
              return tmp;
              break;
            }
    default: {
               return -1;
             }
  }
}

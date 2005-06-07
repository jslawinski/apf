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

#include "server_get.h"
#include <stdlib.h>

int
get_new_socket(int sockfd, char type, struct sockaddr *addr, socklen_t *addrlen, char* tunneltype)
{
  int tmp;
  switch (type) {
    case 0: {
              return accept(sockfd, addr, addrlen);
              break;
            }
    case 1: {
              if (read(sockfd, &tmp, 4) != 4) {
                return -1;
              }
              if (read(sockfd, tunneltype, 1) != 1) {
                return -1;
              }
              if (read(sockfd, addrlen, 4) != 4) {
                return -1;
              }
              if (read(sockfd, addr, *addrlen) != *addrlen) {
                return -1;
              }
              return tmp;
              break;
            }
    default: {
               return -1;
             }
  }
}

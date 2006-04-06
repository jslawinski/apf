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

#include "http_proxy_functions.h"
#include "network.h"
#include "stats.h"
#include "logging.h"

static char isseed;

/*
 * Function name: myrand
 * Description: Returns the pseudo-random number from the given range.
 *              If the lower and upper bounds are the same, the pseudo-random
 *              number is returned from the range (-RAND_MAX, -RAND_MAX+down)
 *              or (down, RAND_MAX).
 * Arguments: down - the lower bound of the range
 *            up - the upper bound of the range
 * Returns: The pseudo-random number from the given range.
 */

int
myrand(int down, int up)
{
	struct timeval tv;
	if (!isseed) {
		gettimeofday(&tv, 0);
		srand(tv.tv_sec);
		isseed = 1;
	}
	return ( down + ( rand() % (up - down + 1) ) );
}

/*
 * Function name: mysleep
 * Description: Sleeps for the given amount of milliseconds.
 * Arguments: time - the amount of milliseconds to sleep for
 */

void
mysleep(double time)
{
	struct timeval tv;
	tv.tv_sec = (int) time;
	tv.tv_usec = (int)(time * 1000000)%1000000;
	select(0, NULL, NULL, NULL, &tv);
}

/*
 * Function name: delete_user
 * Description: Deletes the user's connection from the http proxy connections.
 * Arguments: cnts - the connection to remove
 *            i - the user's number
 *            allset - the set of file descriptors
 */

void
delete_user(connection* cnts, int i, fd_set* allset)
{
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: delete_user(%d)", i);
  clear_fd(&(cnts[i].sockfd), allset);
  if (!(cnts[i].state & C_POST_WAIT)) {
    clear_sslFd(cnts[i].postFd, allset);
  }
  if ((cnts[i].type == 0) && (!(cnts[i].state & C_GET_WAIT))) {
    clear_sslFd(cnts[i].getFd, allset);
  }
  cnts[i].state = C_CLOSED;
  cnts[i].sent_ptr = cnts[i].ptr = cnts[i].length = 0;
  cnts[i].type = 0;
}

/*
 * Function name: parse_header
 * Description: Reads and parses the http header.
 * Arguments: sf - the pointer to SslFd structure
 *            tab - the buffer used for reading the data
 *            hdr - the pointer to header structure
 *            https - the flag indicating if the connection is http/https
 * Returns: 0 - success,
 *          1 - failure.
 */

int
parse_header(SslFd* sf, char* tab, header* hdr, char https)
{
  int n, i, j, state = 0;
  char tmpt[100];
  if (https) {
    n = SSL_read(SslFd_get_ssl(sf), tab, 9000);
  }
  else {
    n = read(SslFd_get_fd(sf), tab, 9000);
  }
  hdr->allreaded = n;
  i = j = 0;
  memset(tmpt, 0, 100);
  hdr->ptr = 0;
  hdr->length = 0;
  while (i < n) {
    if (j == 99)
      return 1;
    switch (state) {
      case 0:
        if ((tab[i] != ' ') && (tab[i] != '\t')) {
          tmpt[j] = tab[i];
          ++j;
        }
        else {
          tmpt[j] = 0;
          if (strcmp(tmpt, "GET") == 0) {
            hdr->type = H_TYPE_GET;
            state = 1;
            break;
          }
          if (strcmp(tmpt, "POST") == 0) {
            hdr->type = H_TYPE_POST;
            state = 1;
            break;
          }
          if ((strcmp(tmpt, "HTTP/1.0") == 0) || (strcmp(tmpt, "HTTP/1.1") == 0)) {
            hdr->type = H_TYPE_OK;
            state = 6;
            break;
          }
          return 1;
        }
        break;
      case 1:
        if ((tab[i] != ' ') && (tab[i] != '\t')) {
          tmpt[0] = tab[i];
          j = 1;
          state = 2;
        }
        break;
      case 2:
        if (tab[i] != '=') {
          tmpt[j] = tab[i];
          ++j;
        }
        else {
          tmpt[j] = 0;
          if (strcmp(tmpt, "/yahpt.html?id")) {
            return 1;
          }
          j = 0;
          state = 3;
        }
        break;
      case 3:
        if ((tab[i] != ' ') && (tab[i] != '\t')) {
          if (j == 9) {
            return 1;
          }
          hdr->id[j] = tab[i];
          ++j;
        }
        else {
          if (j != 9) {
            return 1;
          }
          hdr->id[j] = 0;
          state = 4;
        }
        break;
      case 4:
        if (tab[i] == '\n')
          state = 5;
        break;
      case 5:
        if (tab[i] == '\n') {
          hdr->ptr = i+1;
          hdr->length = n - hdr->ptr;
          return 0;
        }
        if (tab[i] != '\r') {
          state = 4;
        }
        break;
      case 6:
        if ((tab[i] != ' ') && (tab[i] != '\t')) {
          tmpt[0] = tab[i];
          j = 1;
          state = 7;
        }
        break;
      case 7:
        if ((tab[i] == ' ') || (tab[i] == '\t')) {
          tmpt[j] = 0;
          if (strcmp(tmpt, "200")) {
            return 1;
          }
          state = 4;
        }
        else {
          tmpt[j] = tab[i];
          ++j;
        }
        break;
    }
    ++i;
  }
  return 1;
}

/*
 * Function name: set_fd
 * Description: Starts watching the file descriptor.
 * Arguments: fd - the file descriptor
 *            maxfdp1 - the upper limit of the file descriptor numbers
 *            allset - the set of file descriptors
 */

void
set_fd(int fd, int* maxfdp1, fd_set* allset)
{
  FD_SET(fd, allset);
  (*maxfdp1) = ((*maxfdp1) > fd) ? (*maxfdp1) : (fd + 1);
}

/*
 * Function name: close_fd
 * Description: Closes the file descriptor.
 * Arguments: fd - the file descriptor to close
 */

void
close_fd(int* fd)
{
  close(*fd);
}

/*
 * Function name: clear_fd
 * Description: Removes the file descriptor from the set and closes it.
 * Arguments: fd - the file descriptor to remove and close
 *            set - the set of file descriptors
 */

void
clear_fd(int* fd, fd_set* set)
{
  FD_CLR(*fd, set);
  close_fd(fd);
}

/*
 * Function name: read_message
 * Description: Reads the message from the http proxy connection and writes it
 *              to the file descriptor.
 * Arguments: fd - the file descriptor
 *            length - the length of the buffer
 *            client - the http proxy connection
 *            tab - the buffer with the readed data
 *            ptr - the offset from which the data reading will start
 * Returns: 0 - success,
 *          1 - failure.
 */

int
read_message(int fd, int length, connection* client, char* tab, int ptr)
{
  int j = 0;
  int tmp = 0;
  while (j < length) {
    if (client->curreceived + length-j > client->toreceive) {
      if (client->toreceive - client->curreceived > 0) {
        writen(fd, (unsigned char*) (tab+ptr+j), client->toreceive - client->curreceived);
        j += client->toreceive - client->curreceived;
        client->curreceived += client->toreceive - client->curreceived;
      }
      if (client->read_state == 0) {
        switch (tab[ptr + j]) {
          case 'M': {
                      if (j + 5 <= length) {
                        memcpy(&tmp, &tab[ptr + j + 1], 4);
                        client->toreceive = ntohl(tmp);
                        client->curreceived = 0;
                        j += 5;
                      }
                      else if (j + 1 < length) {
                        memcpy(client->readed_length, &tab[ptr + j + 1], length - j - 1);
                        client->read_state = length - j;
                        j += length - j;
                      }
                      else {
                        ++j;
                        client->read_state = 1;
                      }
                      break;
                    }
          case 'T': {
                      ++j;
                      break;
                    }
          case 'A': {
                      ++j;
                      if (client->state == C_CLOSED) {
                        client->state = C_OPEN;
                      }
                      break;
                    }
          default: {
                     return 1;
                   }
        }
      }
      else {
        if (j + 5 - client->read_state <= length) {
          memcpy(&client->readed_length[client->read_state-1], &tab[ptr + j], 5 - client->read_state);
          memcpy(&tmp, client->readed_length, 4);
          client->toreceive = ntohl(tmp);
          client->curreceived = 0;
          j += 5 - client->read_state;
          client->read_state = 0;
        }
        else {
          memcpy(&client->readed_length[client->read_state-1], &tab[ptr + j], length - j);
          client->read_state += length - j;
          j += length -j;
        }
      }
    }
    else if (length-j > 0) {
      client->curreceived += length-j;
      writen(fd, (unsigned char*) (tab+ptr+j), length-j);
      j += length-j;
    }
  }
  return 0;
}

/*
 * Function name: clear_sslFd
 * Description: Close the socket encapsulated in SslFd structure, remove this file descriptor
 *              from fd_set and clear ssl structure.
 * Arguments: sf - pointer to SslFd structure
 *            set - pointer to fd_set structure
 */

void
clear_sslFd(SslFd* sf, fd_set* set)
{
  clear_fd((&(sf->fd)), set);
  if (SslFd_get_ssl(sf)) {
    SSL_clear(SslFd_get_ssl(sf));
  }
}

/*
 * Function name: http_write
 * Description: Write the message via http/https proxy.
 * Arguments: https - if the https proxy will be used instead of http proxy
 *            sf - pointer to SslFd structure
 *            buf - buffer containing the data to send
 *            amount - how much butes will be send
 * Returns: The result of writen or SSL_writen function, depending on 'https' value.
 */

int
http_write(char https, SslFd* sf, unsigned char* buf, int amount)
{
  if (https) {
    return SSL_writen(SslFd_get_ssl(sf), buf, amount);
  }
  else {
    return writen(SslFd_get_fd(sf), buf, amount);
  }
}

/*
 * Function name: http_read
 * Description: Read the message via http/https proxy.
 * Arguments: https - if the https proxy will be used instead of http proxy
 *            sf - pointer to SslFd structure
 *            buf - buffer for the received data
 *            amount - how much bytes will be received
 * Returns: The result of read or SSL_read function, depending on 'https' value.
 */

int
http_read(char https, SslFd* sf, unsigned char* buf, int amount)
{
  if (https) {
    return SSL_read(SslFd_get_ssl(sf), buf, amount);
  }
  else {
    return read(SslFd_get_fd(sf), buf, amount);
  }
}

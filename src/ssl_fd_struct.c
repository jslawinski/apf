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
#include <zlib.h>
#include <assert.h>

#include "activefor.h"
#include "stats.h"
#include "logging.h"
#include "ssl_fd_struct.h"

/*
 * Function name: SslFd_new
 * Description: Create and initialize new SslFd structure.
 * Returns: Pointer to newly created SslFd structure.
 */

SslFd*
SslFd_new()
{
  SslFd* tmp = calloc(1, sizeof(SslFd));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: SslFd_free
 * Description: Free the memory allocated for SslFd structure.
 * Arguments: sf - pointer to pointer to SslFd structure
 */

void
SslFd_free(SslFd** sf)
{
  assert(sf != NULL);
  if (sf == NULL) {
    return;
  }
  assert((*sf) != NULL);
  if ((*sf) == NULL) {
    return;
  }
  if ((*sf)->ssl) {
    SSL_free((*sf)->ssl);
    (*sf)->ssl = NULL;
  }
  free((*sf));
  (*sf) = NULL;
}

/*
 * Function name: SslFd_set_fd
 * Description: Set file descriptor of the used socket.
 * Arguments: sf - pointer to SslFd structure
 *            fd - file descriptor of the used socket
 */

void
SslFd_set_fd(SslFd* sf, int fd)
{
  assert(sf != NULL);
  if (sf == NULL) {
    return;
  }
  sf->fd = fd;
}

/*
 * Function name: SslFd_set_ssl_general
 * Description: Set ssl object for the used socket. Free previous ssl object if 'free' argument is not 0.
 * Arguments: sf - pointer to SslFd structure
 *            fd - ssl object for the used socket
 *            free - free previous ssl object
 */

void
SslFd_set_ssl_general(SslFd* sf, SSL* ssl, int free)
{
  assert(sf != NULL);
  if (sf == NULL) {
    return;
  }
  if ((free) && (sf->ssl)) {
    SSL_free(sf->ssl);
  }
  sf->ssl = ssl;
}


/*
 * Function name: SslFd_set_ssl
 * Description: Set ssl object for the used socket.
 * Arguments: sf - pointer to SslFd structure
 *            fd - ssl object for the used socket
 */

void
SslFd_set_ssl(SslFd* sf, SSL* ssl)
{
  SslFd_set_ssl_general(sf, ssl, 1);
}

/*
 * Function name: SslFd_set_ssl_nf
 * Description: Set ssl object for the used socket. Don't free previous ssl object
 * Arguments: sf - pointer to SslFd structure
 *            fd - ssl object for the used socket
 */

void
SslFd_set_ssl_nf(SslFd* sf, SSL* ssl)
{
  SslFd_set_ssl_general(sf, ssl, 0);
}

/*
 * Function name: SslFd_set_ssl
 * Description: Get file descriptor of the used socket.
 * Arguments: sf - pointer to SslFd structure
 * Returns: File descriptor of the used socket.
 */

int
SslFd_get_fd(SslFd* sf)
{
  assert(sf != NULL);
  if (sf == NULL) {
    return -1;
  }
  return sf->fd;
}

/*
 * Function name: SslFd_get_ssl
 * Description: Get ssl object for the used socket.
 * Arguments: sf - pointer to SslFd structure
 * Returns: Ssl object for the used socket.
 */

SSL*
SslFd_get_ssl(SslFd* sf)
{
  assert(sf != NULL);
  if (sf == NULL) {
    return NULL;
  }
  return sf->ssl;
}

/*
 * Function name: SslFd_send_message
 * Description: Send message from 'buf' of the length 'amount' to the socket
 *              encapsulated in SslFd structure. 'type' is used to keep
 *              information about ip family, using of ssl, using of zlib and more.
 * Arguments: type - type of the connection
 *            sf - pointer to SslFd structure
 *            buf - buffer which keeps data to send
 *            amount - amount of data to send
 * Returns: Amount of bytes written or -1, if some error occured.
 */

int
SslFd_send_message(char type, SslFd* sf, unsigned char* buf, int amount)
{
  unsigned long clen;
  int length;
  static unsigned char buffer[9000];

  assert(sf != NULL);
  assert(buf != NULL);
  
  if ((sf == NULL) || (buf == NULL)) {
    return -1;
  }

  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "send_message: ssl:%s zlib:%s length:%d", (TYPE_IS_SSL(type))?"yes":"no",
      (TYPE_IS_ZLIB(type))?"yes":"no", amount);
  clen = 8995;
  length = amount - 5;
  if (TYPE_IS_ZLIB(type)) {
    memcpy(buffer, buf, 5);
    if (amount > 5) {
      compress(&buffer[5], &clen, &buf[5], length);
      if (clen < length) {
        length = clen;
        TYPE_SET_COMP(length);
        buffer[3] = length >> 8; /* high bits of message length */
        buffer[4] = length;  /* low bits of message length */
        addtocg(amount-5 - clen);
      }
    }
    if (TYPE_IS_SSL(type)) {
      if (TYPE_IS_COMP(length)) {
        return SSL_writen(sf->ssl, buffer, clen+5);
      }
      else {
        return SSL_writen(sf->ssl, buf, amount);
      }
    }
    else {
      if (TYPE_IS_COMP(length)) {
        return writen(sf->fd, buffer, clen+5);
      }
      else {
        return writen(sf->fd, buf, amount);
      }
    }
  }
  else {
    if (TYPE_IS_SSL(type)) {
      return SSL_writen(sf->ssl, buf, amount);
    }
    else {
      return writen(sf->fd, buf, amount);
    }
  }
}

/*
 * Function name: SslFd_get_message
 * Description: Get message from the socket encapsulated in SslFd structure
 *              and write it to the 'buf'. Message is 'amount' butes long.
 *              'type' is used to keep information about ip family, using of
 *              ssl, using of zlib and more.
 * Arguments: type - type of the connection
 *            sf - pointer to SslFd structure
 *            buf - buffer which will keep received data
 *            amount - length of the message to receive
 * Returns: Amount of bytes received or -1, if some error occured.
 */

int
SslFd_get_message(char type, SslFd* sf, unsigned char* buf, int amount)
{
  int length;
  unsigned long elen;
  static unsigned char bufor[9000];
  
  assert(sf != NULL);
  assert(buf != NULL);
  
  if ((sf == NULL) || (buf == NULL)) {
    return -1;
  }
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "get_message: ssl:%s zlib:%s length:%d", (TYPE_IS_SSL(type))?"yes":"no",
      (TYPE_IS_ZLIB(type))?"yes":"no", amount);
  if (amount < 0) {
    if (TYPE_IS_SSL(type)) {
      return SSL_read(sf->ssl, buf, -amount);
    }
    else {
      return read(sf->fd, buf, -amount);
    }
  }
  if (TYPE_IS_ZLIB(type)) {
    if (TYPE_IS_SSL(type)) {
      length = SSL_readn(sf->ssl, bufor, amount&0xBFFF);
    }
    else {
      length = readn(sf->fd, bufor, amount&0xBFFF);
    }
    if (length <= 0) return length;
    elen = 8096;
    if (TYPE_IS_COMP(amount)) {
      uncompress(buf, &elen, bufor, length);
    }
    else {
      memcpy(buf, bufor, length);
      elen = length;
    }
    return elen;
  }
  else
  {
    if (TYPE_IS_SSL(type)) {
      return SSL_readn(sf->ssl, buf, amount);
    }
    else {
      return readn(sf->fd, buf, amount);
    }
  }
}

/*
 * Function name: SslFd_swap_content
 * Description: Swap the content of two SslFd structures.
 * Arguments: sf1 - first pointer to SslFd structure
 *            sf2 - second pointer to SslFd structure
 */

void
SslFd_swap_content(SslFd* sf1, SslFd* sf2)
{
  int tmpfd;
  SSL* tmpssl;
  
  assert(sf1 != NULL);
  assert(sf2 != NULL);

  tmpfd = SslFd_get_fd(sf1);
  tmpssl = SslFd_get_ssl(sf2);
  SslFd_set_fd(sf1, SslFd_get_fd(sf2));
  SslFd_set_ssl(sf1, SslFd_get_ssl(sf2));
  SslFd_set_fd(sf2, tmpfd);
  SslFd_set_ssl(sf2, tmpssl);
}

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

#include "make_ssl_handshake.h"
#include "stats.h"

#include <config.h>

#include <errno.h>
#include <openssl/err.h>

void
make_ssl_initialize(clifd *cliconn)
{
  if (SSL_set_fd(cliconn->ssl, cliconn->commfd) != 1) {
    aflog(0, "Problem with initializing ssl... exiting");
    exit(1);
  }
}

int
make_ssl_accept(clifd *cliconn)
{
  int result;
  if ((result = SSL_accept(cliconn->ssl)) != 1) {
    return get_ssl_error(cliconn, "  SSL_accept has failed", result);
  }
  return 0;
}

int
get_ssl_error(clifd *cliconn, char* info, int result)
{
  int merror;
#ifdef HAVE_ERR_ERROR_STRING
  char err_buff[200];
#endif
  merror = SSL_get_error(cliconn->ssl, result);
  switch (merror) {
    case SSL_ERROR_NONE : {
                            aflog(2, "%s(%d): none", info, result);
                            break;
                          }
    case SSL_ERROR_ZERO_RETURN : {
                                   aflog(2, "%s(%d): zero", info, result);
                                   break;
                                 }
    case SSL_ERROR_WANT_READ : { 
                                 aflog(2, "%s(%d): w_read", info, result);
                                 break;
                               }
    case SSL_ERROR_WANT_WRITE : {
                                  aflog(2, "%s(%d): w_write", info, result);
                                  break;
                                }
    case SSL_ERROR_WANT_CONNECT : {
                                    aflog(2, "%s(%d): w_connect", info, result);
                                    break;
                                  }
    case SSL_ERROR_WANT_X509_LOOKUP : {
                                        aflog(2, "%s(%d): w_x509_lookup", info, result);
                                        break;
                                      }
    case SSL_ERROR_SYSCALL : {
                               aflog(2, "%s(%d): syscall", info, result);
                               break;
                             }
    case SSL_ERROR_SSL : {
                           SSL_load_error_strings();
#ifdef HAVE_ERR_ERROR_STRING
                           aflog(2, "%s(%d): ssl:%s", info, result,
                               ERR_error_string(ERR_get_error(), err_buff));
#else
                           aflog(2, "%s(%d): ssl", info, result);
#endif
                           break;
                         }
    default: {
               aflog(2, "%s(%d): unrecognized error (%d)", info, result, errno);
             }
  }
  if (merror == SSL_ERROR_WANT_READ) {
    return 1;
  }
  return 2;
}

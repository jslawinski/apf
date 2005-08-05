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


#ifndef _JS_SSL_FD_STRUCT_H
#define _JS_SSL_FD_STRUCT_H

#include <openssl/ssl.h>

typedef struct {
  int fd;
  SSL* ssl;
} SslFd;

/* 'constructor' */
SslFd* SslFd_new();
/* 'destructor' */
void SslFd_free(SslFd** sf);
/* setters */
void SslFd_set_fd(SslFd* sf, int fd);
void SslFd_set_ssl(SslFd* sf, SSL* ssl);
void SslFd_set_ssl_nf(SslFd* sf, SSL* ssl);
/* getters */
int SslFd_get_fd(SslFd* sf);
SSL* SslFd_get_ssl(SslFd* sf);
/* other */
int SslFd_send_message(char type, SslFd* sf, unsigned char* buf, int amount);
int SslFd_get_message(char type, SslFd* sf, unsigned char* buf, int amount);
void SslFd_swap_content(SslFd* sf1, SslFd* sf2);

#endif

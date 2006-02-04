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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>

#include "ssl_fd_struct.h"

#ifndef _JS_HTTP_PROXY_FUNCTIONS_H
#define _JS_HTTP_PROXY_FUNCTIONS_H

#define C_CLOSED 0
#define C_POST_WAIT 1
#define C_GET_WAIT 2
#define C_OPEN 4

#define H_TYPE_GET 0
#define H_TYPE_POST 1
#define H_TYPE_OK 2
#define H_TYPE_ERROR 3

typedef struct {
  char type;
  char id[10];
  int ptr;
  int length;
  int allreaded;
} header;

typedef struct {
  char read_state;
  char readed_length[4];
  char state;
  char id[10];
  SslFd* postFd;
  SslFd* getFd;
  int sent_ptr;
  int sockfd;
  char buf[9000];
  char tmpbuf[9000];
  char tmpstate;
  SslFd* tmpFd;
  char type;
  header tmpheader;
  int ptr;
  int length;
  int curreceived;
  int toreceive;
  int received;
} connection;

int myrand(int, int);
void mysleep(double);
int parse_header(SslFd*, char*, header*, char);
int read_message(int, int, connection*, char*, int);
void delete_user(connection*, int, fd_set*);
void set_fd(int, int*, fd_set*);
void close_fd(int*);
void clear_fd(int*, fd_set*);
void clear_sslFd(SslFd*, fd_set*);
int http_write(char, SslFd*, unsigned char*, int);
int http_read(char, SslFd*, unsigned char*, int);

#endif

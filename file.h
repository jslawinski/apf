/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003,2004 jeremian <jeremian [at] poczta.fm>
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

#include "activefor.h"
#include "network.h"
#include <openssl/ssl.h>

#ifndef _JS_FILE_H
#define _JS_FILE_H

#define  F_UNKNOWN  1
#define  F_IGNORE   2
#define  F_ROPTION  3
#define  F_RVALUE   4
#define  F_MIDDLE   5

typedef struct {
  char* hostname;
  char* lisportnum;
  char* manportnum;
  char* users;
  char* clients; 
  char* usrpcli; 
  char* clim; 
  char* timeout;
  unsigned char pass[4];
  int usercon;
  int usernum;
  int clicon; 
  int clinum; 
  int upcnum; 
  int tmout;
  int listenfd;
  int managefd;
  int climode;
  char type;
  socklen_t addrlen;
  struct sockaddr* cliaddr;
  ConnectuserT* contable;
  ConnectclientT* clitable;
} RealmT;

typedef struct {
  char* certif;
  char* keys;
  char* logfnam;
  char logging;
  int size;
  RealmT* realmtable;
} ConfigurationT;

ConfigurationT parsefile(char*, int*); /* parse the cfg file */

#endif


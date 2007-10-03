/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2007 jeremian <jeremian [at] poczta.fm>
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


#ifndef _JS_CLIENT_CONFIGURATION_STRUCT_H
#define _JS_CLIENT_CONFIGURATION_STRUCT_H

#include "client_realm_struct.h"

typedef struct {
  char* keysFile;
  char* storeFile;
  char* dateFormat;
  int realmsNumber;
  char ignorePublicKeys;
  ClientRealm** realmsTable;
} ClientConfiguration;

/* 'constructor' */
ClientConfiguration* ClientConfiguration_new();
/* 'destructor' */
void ClientConfiguration_free(ClientConfiguration** cc);
/* setters */
void ClientConfiguration_set_keysFile(ClientConfiguration* cc, char* keysFile);
void ClientConfiguration_set_storeFile(ClientConfiguration* cc, char* storeFile);
void ClientConfiguration_set_dateFormat(ClientConfiguration* cc, char* dateFormat);
void ClientConfiguration_set_realmsNumber(ClientConfiguration* cc, int realmsNumber);
void ClientConfiguration_set_realmsTable(ClientConfiguration* cc, ClientRealm** realmsTable);
void ClientConfiguration_set_ignorePublicKeys(ClientConfiguration* cc, char ignorePublicKeys);
/* getters */
char* ClientConfiguration_get_keysFile(ClientConfiguration* cc);
char* ClientConfiguration_get_storeFile(ClientConfiguration* cc);
char* ClientConfiguration_get_dateFormat(ClientConfiguration* cc);
int ClientConfiguration_get_realmsNumber(ClientConfiguration* cc);
ClientRealm** ClientConfiguration_get_realmsTable(ClientConfiguration* cc);
char ClientConfiguration_get_ignorePublicKeys(ClientConfiguration* cc);

#endif

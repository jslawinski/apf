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


#ifndef _JS_SERVER_CONFIGURATION_STRUCT_H
#define _JS_SERVER_CONFIGURATION_STRUCT_H

#include "server_realm_struct.h"

typedef struct {
  char* cacertificateFile;
  char* cacertificatePath;
  char* sCertificateDepth;
  int certificateDepth;
  char* certificateFile;
  char* keysFile;
  char* dateFormat;
  int realmsNumber;
  time_t startTime;
  ServerRealm** realmsTable;
} ServerConfiguration;

/* 'constructor' */
ServerConfiguration* ServerConfiguration_new();
/* 'destructor' */
void ServerConfiguration_free(ServerConfiguration** sc);
/* setters */
void ServerConfiguration_set_certificateFile(ServerConfiguration* sc, char* certificateFile);
void ServerConfiguration_set_cacertificateFile(ServerConfiguration* sc, char* cacertificateFile);
void ServerConfiguration_set_cacertificatePath(ServerConfiguration* sc, char* cacertificatePath);
void ServerConfiguration_set_sCertificateDepth(ServerConfiguration* sc, char* sCertificateDepth);
void ServerConfiguration_set_certificateDepth(ServerConfiguration* sc, int certificateDepth);
void ServerConfiguration_set_keysFile(ServerConfiguration* sc, char* keysFile);
void ServerConfiguration_set_dateFormat(ServerConfiguration* sc, char* dateFormat);
void ServerConfiguration_set_realmsNumber(ServerConfiguration* sc, int realmsNumber);
void ServerConfiguration_set_startTime(ServerConfiguration* sc, time_t startTime);
void ServerConfiguration_set_realmsTable(ServerConfiguration* sc, ServerRealm** realmsTable);
/* getters */
char* ServerConfiguration_get_certificateFile(ServerConfiguration* sc);
char* ServerConfiguration_get_cacertificateFile(ServerConfiguration* sc);
char* ServerConfiguration_get_cacertificatePath(ServerConfiguration* sc);
char* ServerConfiguration_get_sCertificateDepth(ServerConfiguration* sc);
int ServerConfiguration_get_certificateDepth(ServerConfiguration* sc);
char* ServerConfiguration_get_keysFile(ServerConfiguration* sc);
char* ServerConfiguration_get_dateFormat(ServerConfiguration* sc);
int ServerConfiguration_get_realmsNumber(ServerConfiguration* sc);
time_t ServerConfiguration_get_startTime(ServerConfiguration* sc);
ServerRealm** ServerConfiguration_get_realmsTable(ServerConfiguration* sc);

#endif

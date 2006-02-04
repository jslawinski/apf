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

#include <stdlib.h>
#include <string.h>

#include "string_functions.h"
#include "server_configuration_struct.h"

/*
 * Function name: ServerConfiguration_new
 * Description: Create and initialize new ServerConfiguration structure.
 * Returns: Pointer to newly created ServerConfiguration structure.
 */

ServerConfiguration*
ServerConfiguration_new()
{
  ServerConfiguration* tmp = calloc(1, sizeof(ServerConfiguration));
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: ServerConfiguration_free
 * Description: Free the memory allocated for ServerConfiguration structure.
 * Arguments: sc - pointer to pointer to ServerConfiguration structure
 */

void
ServerConfiguration_free(ServerConfiguration** sc)
{
  int i;
  if (sc == NULL) {
    return;
  }
  if ((*sc) == NULL) {
    return;
  }
  if ((*sc)->certificateFile) {
    free((*sc)->certificateFile);
    (*sc)->certificateFile = NULL;
  }
  if ((*sc)->keysFile) {
    free((*sc)->keysFile);
    (*sc)->keysFile = NULL;
  }
  if ((*sc)->dateFormat) {
    free((*sc)->dateFormat);
    (*sc)->dateFormat = NULL;
  }
  if ((*sc)->realmsTable) {
    for (i = 0; i < (*sc)->realmsNumber; ++i) {
      if ((*sc)->realmsTable[i]) {
        ServerRealm_free(&((*sc)->realmsTable[i]));
      }
    }
    free((*sc)->realmsTable);
    (*sc)->realmsTable = NULL;
  }
  free((*sc));
  (*sc) = NULL;
}

/*
 * Function name: ServerConfiguration_set_certificateFile
 * Description: Set certificate filename.
 * Arguments: sc - pointer to ServerConfiguration structure
 *            certificateFile - certificate filename
 */

void
ServerConfiguration_set_certificateFile(ServerConfiguration* sc, char* certificateFile)
{
  if (sc == NULL) {
    return;
  }
  string_cp(&(sc->certificateFile), certificateFile);
}

/*
 * Function name: ServerConfiguration_set_keysFile
 * Description: Set keys filename.
 * Arguments: sc - pointer to ServerConfiguration structure
 *            keysFile - keys filename
 */

void
ServerConfiguration_set_keysFile(ServerConfiguration* sc, char* keysFile)
{
  if (sc == NULL) {
    return;
  }
  string_cp(&(sc->keysFile), keysFile);
}

/*
 * Function name: ServerConfiguration_set_dateFormat
 * Description: Set format of the date string.
 * Arguments: sc - pointer to ServerConfiguration structure
 *            dateFormat - format of the date string
 */

void
ServerConfiguration_set_dateFormat(ServerConfiguration* sc, char* dateFormat)
{
  if (sc == NULL) {
    return;
  }
  string_cp(&(sc->dateFormat), dateFormat);
}

/*
 * Function name: ServerConfiguration_set_realmsNumber
 * Description: Set number of realms.
 * Arguments: sc - pointer to ServerConfiguration structure
 *            realmsNumber - number of realms
 */

void
ServerConfiguration_set_realmsNumber(ServerConfiguration* sc, int realmsNumber)
{
  if (sc == NULL) {
    return;
  }
  sc->realmsNumber = realmsNumber;
}

/*
 * Function name: ServerConfiguration_set_startTime
 * Description: Set start time of the server.
 * Arguments: sc - pointer to ServerConfiguration structure
 *            startTime - start time of the server
 */

void
ServerConfiguration_set_startTime(ServerConfiguration* sc, time_t startTime)
{
  if (sc == NULL) {
    return;
  }
  sc->startTime = startTime;
}

/*
 * Function name: ServerConfiguration_set_realmsTable
 * Description: Set table of realms.
 * Arguments: sc - pointer to ServerConfiguration structure
 *            realmsTable - table of realms
 */

void
ServerConfiguration_set_realmsTable(ServerConfiguration* sc, ServerRealm** realmsTable)
{
  int i;
  if (sc == NULL) {
    return;
  }
  if (sc->realmsTable) {
    for (i = 0; i < sc->realmsNumber; ++i) {
      if (sc->realmsTable[i]) {
        ServerRealm_free(&(sc->realmsTable[i]));
      }
    }
    free(sc->realmsTable);
    sc->realmsTable = NULL;
  }
  sc->realmsTable = realmsTable;
}

/*
 * Function name: ServerConfiguration_get_certificateFile
 * Description: Get certificate filename.
 * Arguments: sc - pointer to ServerConfiguration structure
 * Returns: Certificate filename.
 */

char*
ServerConfiguration_get_certificateFile(ServerConfiguration* sc)
{
  if (sc == NULL) {
    return NULL;
  }
  return sc->certificateFile;
}

/*
 * Function name: ServerConfiguration_get_keysFile
 * Description: Get keys filename.
 * Arguments: sc - pointer to ServerConfiguration structure
 * Returns: Keys filename.
 */

char*
ServerConfiguration_get_keysFile(ServerConfiguration* sc)
{
  if (sc == NULL) {
    return NULL;
  }
  return sc->keysFile;
}

/*
 * Function name: ServerConfiguration_get_dateFormat
 * Description: Get format of the date string.
 * Arguments: sc - pointer to ServerConfiguration structure
 * Returns: Format of the date string.
 */

char*
ServerConfiguration_get_dateFormat(ServerConfiguration* sc)
{
  if (sc == NULL) {
    return NULL;
  }
  return sc->dateFormat;
}

/*
 * Function name: ServerConfiguration_get_realmsNumber
 * Description: Get number of realms.
 * Arguments: sc - pointer to ServerConfiguration structure
 * Returns: Number of realms.
 */

int
ServerConfiguration_get_realmsNumber(ServerConfiguration* sc)
{
  if (sc == NULL) {
    return -1;
  }
  return sc->realmsNumber;
}

/*
 * Function name: ServerConfiguration_get_startTime
 * Description: Get start time of the server.
 * Arguments: sc - pointer to ServerConfiguration structure
 * Returns: Start time of the server.
 */

time_t
ServerConfiguration_get_startTime(ServerConfiguration* sc)
{
  if (sc == NULL) {
    return 0;
  }
  return sc->startTime;
}

/*
 * Function name: ServerConfiguration_get_realmsTable
 * Description: Get table of realms.
 * Arguments: sc - pointer to ServerConfiguration structure
 * Returns: Table of realms.
 */

ServerRealm**
ServerConfiguration_get_realmsTable(ServerConfiguration* sc)
{
  if (sc == NULL) {
    return NULL;
  }
  return sc->realmsTable;
}

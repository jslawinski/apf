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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "string_functions.h"
#include "client_configuration_struct.h"

/*
 * Function name: ClientConfiguration_new
 * Description: Create and initialize new ClientConfiguration structure.
 * Returns: Pointer to newly created ClientConfiguration structure.
 */

ClientConfiguration*
ClientConfiguration_new()
{
  ClientConfiguration* tmp = calloc(1, sizeof(ClientConfiguration));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: ClientConfiguration_free
 * Description: Free the memory allocated for ClientConfiguration structure.
 * Arguments: cc - pointer to pointer to ClientConfiguration structure
 */

void
ClientConfiguration_free(ClientConfiguration** cc)
{
  int i;
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  assert((*cc) != NULL);
  if ((*cc) == NULL) {
    return;
  }
  if ((*cc)->keysFile) {
    free((*cc)->keysFile);
    (*cc)->keysFile = NULL;
  }
  if ((*cc)->certificateFile) {
    free((*cc)->certificateFile);
    (*cc)->certificateFile = NULL;
  }
  if ((*cc)->storeFile) {
    free((*cc)->storeFile);
    (*cc)->storeFile = NULL;
  }
  if ((*cc)->realmsTable) {
    for (i = 0; i < (*cc)->realmsNumber; ++i) {
      if ((*cc)->realmsTable[i]) {
        ClientRealm_free(&((*cc)->realmsTable[i]));
      }
    }
    free((*cc)->realmsTable);
    (*cc)->realmsTable = NULL;
  }
  free((*cc));
  (*cc) = NULL;
}

/*
 * Function name: ClientConfiguration_set_keysFile
 * Description: Set keys filename.
 * Arguments: cc - pointer to ClientConfiguration structure
 *            keysFile - keys filename
 */

void
ClientConfiguration_set_keysFile(ClientConfiguration* cc, char* keysFile)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  string_cp(&(cc->keysFile), keysFile);
}

/*
 * Function name: ClientConfiguration_set_certificateFile
 * Description: Set certs filename.
 * Arguments: cc - pointer to ClientConfiguration structure
 *            certificateFile - certs filename
 */

void
ClientConfiguration_set_certificateFile(ClientConfiguration* cc, char* certificateFile)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  string_cp(&(cc->certificateFile), certificateFile);
}

/*
 * Function name: ClientConfiguration_set_storeFile
 * Description: Set store filename.
 * Arguments: cc - pointer to ClientConfiguration structure
 *            storeFile - store filename
 */

void
ClientConfiguration_set_storeFile(ClientConfiguration* cc, char* storeFile)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  string_cp(&(cc->storeFile), storeFile);
}

/*
 * Function name: ClientConfiguration_set_dateFormat
 * Description: Set format of the date string.
 * Arguments: cc - pointer to ClientConfiguration structure
 *            dateFormat - format of the date string
 */

void
ClientConfiguration_set_dateFormat(ClientConfiguration* cc, char* dateFormat)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  string_cp(&(cc->dateFormat), dateFormat);
}

/*
 * Function name: ClientConfiguration_set_realmsNumber
 * Description: Set number of realms.
 * Arguments: cc - pointer to ClientConfiguration structure
 *            realmsNumber - number of realms
 */

void
ClientConfiguration_set_realmsNumber(ClientConfiguration* cc, int realmsNumber)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  cc->realmsNumber = realmsNumber;
}

/*
 * Function name: ClientConfiguration_set_realmsTable
 * Description: Set table of realms.
 * Arguments: cc - pointer to ClientConfiguration structure
 *            realmsTable - table of realms
 */

void
ClientConfiguration_set_realmsTable(ClientConfiguration* cc, ClientRealm** realmsTable)
{
  int i;
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  if (cc->realmsTable) {
    for (i = 0; i < cc->realmsNumber; ++i) {
      if (cc->realmsTable[i]) {
        ClientRealm_free(&(cc->realmsTable[i]));
      }
    }
    free(cc->realmsTable);
    cc->realmsTable = NULL;
  }
  cc->realmsTable = realmsTable;
}

/*
 * Function name: ClientConfiguration_set_ignorePublicKeys
 * Description: Enable/disable the public keys checking.
 * Arguments: cc - pointer to ClientConfiguration structure
 *            ignorePublicKeys - if the public keys checking is enabled/disabled
 */

void
ClientConfiguration_set_ignorePublicKeys(ClientConfiguration* cc, char ignorePublicKeys)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return;
  }
  cc->ignorePublicKeys = ignorePublicKeys;
}

/*
 * Function name: ClientConfiguration_get_keysFile
 * Description: Get keys filename.
 * Arguments: cc - pointer to ClientConfiguration structure
 * Returns: Keys filename.
 */

char*
ClientConfiguration_get_keysFile(ClientConfiguration* cc)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return NULL;
  }
  return cc->keysFile;
}

/*
 * Function name: ClientConfiguration_get_certificateFile
 * Description: Get certs filename.
 * Arguments: cc - pointer to ClientConfiguration structure
 * Returns: Certs filename.
 */

char*
ClientConfiguration_get_certificateFile(ClientConfiguration* cc)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return NULL;
  }
  return cc->certificateFile;
}

/*
 * Function name: ClientConfiguration_get_storeFile
 * Description: Get store filename.
 * Arguments: cc - pointer to ClientConfiguration structure
 * Returns: Store filename.
 */

char*
ClientConfiguration_get_storeFile(ClientConfiguration* cc)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return NULL;
  }
  return cc->storeFile;
}

/*
 * Function name: ClientConfiguration_get_dateFormat
 * Description: Get format of the date string.
 * Arguments: cc - pointer to ClientConfiguration structure
 * Returns: Format of the date string.
 */

char*
ClientConfiguration_get_dateFormat(ClientConfiguration* cc)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return NULL;
  }
  return cc->dateFormat;
}

/*
 * Function name: ClientConfiguration_get_realmsNumber
 * Description: Get number of realms.
 * Arguments: cc - pointer to ClientConfiguration structure
 * Returns: Number of realms.
 */

int
ClientConfiguration_get_realmsNumber(ClientConfiguration* cc)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return -1;
  }
  return cc->realmsNumber;
}

/*
 * Function name: ClientConfiguration_get_realmsTable
 * Description: Get table of realms.
 * Arguments: cc - pointer to ClientConfiguration structure
 * Returns: Table of realms.
 */

ClientRealm**
ClientConfiguration_get_realmsTable(ClientConfiguration* cc)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return NULL;
  }
  return cc->realmsTable;
}

/*
 * Function name: ClientConfiguration_get_ignorePublicKeys
 * Description: Check if the public keys checking is enabled/disabled
 * Arguments: cc - pointer to ClientConfiguration structure
 * Returns: If the public keys checking is enabled/disabled.
 */

char
ClientConfiguration_get_ignorePublicKeys(ClientConfiguration* cc)
{
  assert(cc != NULL);
  if (cc == NULL) {
    return 0;
  }
  return cc->ignorePublicKeys;
}

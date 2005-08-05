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

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include "usr_cli_struct.h"
#include "string_functions.h"

/*
 * Function name: UsrCli_new
 * Description: Create and initialize new UsrCli structure.
 * Returns: Newly created UsrCli structure.
 */

UsrCli*
UsrCli_new()
{
  UsrCli* tmp = calloc(1, sizeof(UsrCli));
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: UsrCli_free
 * Description: Free the memory allocated for UsrCli structure.
 * Arguments: uc - pointer to pointer to UsrCli structure
 */

void
UsrCli_free(UsrCli** uc)
{
  if (uc == NULL) {
    return;
  }
  if ((*uc) == NULL) {
    return;
  }
  if ((*uc)->listenPortName) {
    free((*uc)->listenPortName);
    (*uc)->listenPortName = NULL;
  }
  if ((*uc)->managePortName) {
    free((*uc)->managePortName);
    (*uc)->managePortName = NULL;
  }
  free((*uc));
  (*uc) = NULL;
}

/* Function name: UsrCli_set_listenPortName
 * Description: Set listen port name.
 * Arguments: uc - pointer to UsrCli structure
 *            listenPortName - listen port name
 */

void
UsrCli_set_listenPortName(UsrCli* uc, char* listenPortName)
{
  char* tmp;
  if (uc == NULL) {
    return;
  }
  if ((tmp = rindex(listenPortName, ':')) != NULL) {
    (*tmp) = 0;
    ++tmp;
    string_cp(&(uc->listenHostName), listenPortName);
    string_cp(&(uc->listenPortName), tmp);
  }
  else {
    string_cp(&(uc->listenPortName), listenPortName);
  }
}

/*
 * Function name: UsrCli_set_managePortName
 * Description: Set manage port name.
 * Arguments: uc - pointer to UsrCli structure
 *            managePortName - manage port name
 */

void
UsrCli_set_managePortName(UsrCli* uc, char* managePortName)
{
  char* tmp;
  if (uc == NULL) {
    return;
  }
  if ((tmp = rindex(managePortName, ':')) != NULL) {
    (*tmp) = 0;
    ++tmp;
    string_cp(&(uc->manageHostName), managePortName);
    string_cp(&(uc->managePortName), tmp);
  }
  else {
    string_cp(&(uc->managePortName), managePortName);
  }
}

/*
 * Function name: UsrCli_set_listenFd
 * Description: Set listen file descriptor.
 * Arguments: uc - pointer to UsrCli structure
 *            listenFd - listen file descriptor
 */

void
UsrCli_set_listenFd(UsrCli* uc, int listenFd)
{
  if (uc == NULL) {
    return;
  }
  uc->listenFd = listenFd;
}

/*
 * Function name: UsrCli_set_manageFd
 * Description: Set manage file descriptor.
 * Arguments: uc - pointer to UsrCli structure
 *            manageFd - manage file descriptor
 */

void
UsrCli_set_manageFd(UsrCli* uc, int manageFd)
{
  if (uc == NULL) {
    return;
  }
  uc->manageFd = manageFd;
}

/* Function name: UsrCli_get_listenPortName
 * Description: Get listen port name.
 * Arguments: uc - pointer to UsrCli structure
 * Returns: Listen port name.
 */

char*
UsrCli_get_listenPortName(UsrCli* uc)
{
  if (uc == NULL) {
    return NULL;
  }
  return uc->listenPortName;
}

/*
 * Function name: UsrCli_get_managePortName
 * Description: Get manage port name.
 * Arguments: uc - pointer to UsrCli structure
 * Returns: Manage port name.
 */

char*
UsrCli_get_managePortName(UsrCli* uc)
{
  if (uc == NULL) {
    return NULL;
  }
  return uc->managePortName;
}

/*
 * Function name: UsrCli_get_listenFd
 * Description: Get listen file descriptor.
 * Arguments: uc - pointer to UsrCli structure
 * Returns: Listen file descriptor.
 */

int
UsrCli_get_listenFd(UsrCli* uc)
{
  if (uc == NULL) {
    return -1;
  }
  return uc->listenFd;
}

/*
 * Function name: UsrCli_get_manageFd
 * Description: Get manage file descriptor.
 * Arguments: uc - pointer to UsrCli structure
 * Returns: Manage file desciptor.
 */

int
UsrCli_get_manageFd(UsrCli* uc)
{
  if (uc == NULL) {
    return -1;
  }
  return uc->manageFd;
}

/*
 * Function name: UsrCli_get_listenHostName
 * Description: Get host name used for listenFd in ip_connect function or NULL, if not set.
 * Arguments: uc - pointer to UsrCli structure
 * Returns: Host name used for listenFd in ip_connect function or NULL, if not set.
 */

char*
UsrCli_get_listenHostName(UsrCli* uc)
{
  if (uc == NULL) {
    return NULL;
  }
  return uc->listenHostName;
}

/*
 * Function name: UsrCli_get_manageHostName
 * Description: Get host name used for manageFd in ip_connect function or NULL, if not set.
 * Arguments: uc - pointer to UsrCli structure
 * Returns: Host name used for manageFd in ip_connect function or NULL, if not set.
 */

char*
UsrCli_get_manageHostName(UsrCli* uc)
{
  if (uc == NULL) {
    return NULL;
  }
  return uc->manageHostName;
}

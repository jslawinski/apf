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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssl_routines.h"

/*
 * Function name: check_public_key
 * Description: Checks if the public key is trusted.
 * Arguments: filename - the name of the file with stored keys
 *            hostname - the name of the host
 *            keyhash - the hash of the key
 * Returns: The result of the check.
 */

int
check_public_key(char* filename, char* hostname, char* keyhash)
{
  FILE* storefile;
  char buff[256];
  int lspaceind, i;

  assert(filename != NULL);
  assert(hostname != NULL);
  assert(keyhash != NULL);

  memset(buff, 0, 256);
  
  storefile = fopen(filename, "r");
  if (storefile == NULL) {
    return SSL_PUBLIC_KEY_NOT_KNOWN;
  }

  while (fgets(buff, 256, storefile) != NULL) {
    lspaceind = -1;
    for (i = 0; i < 256; ++i) {
      if (buff[i] == 0) {
        break;
      }
      if (buff[i] == ' ') {
        lspaceind = i;
      }
    }
    if (lspaceind == -1) {
      continue;
    }
    if (buff[strlen(buff)-1] == '\n') {
      buff[strlen(buff)-1] = 0;
    }
    buff[lspaceind] = 0;
    if (strcmp(buff, hostname) == 0) {
      if (strcmp(&buff[lspaceind+1], keyhash) == 0) {
        return SSL_PUBLIC_KEY_VALID;
      }
      else {
        return SSL_PUBLIC_KEY_INVALID;
      }
    }
  }
  return SSL_PUBLIC_KEY_NOT_KNOWN;
}

/*
 * Function name: add_public_key
 * Description: Adds the key to the store file.
 * Arguments: filename - the name of the file with stored keys
 *            hostname - the name of the host
 *            keyhash - the hash of the key
 */

void
add_public_key(char* filename, char* hostname, char* keyhash)
{
  FILE* storefile;
  
  assert(filename != NULL);
  assert(hostname != NULL);
  assert(keyhash != NULL);

  storefile = fopen(filename, "a");
  if (storefile == NULL) {
    return;
  }
  fprintf(storefile, "%s %s\n", hostname, keyhash);
  fclose(storefile);
}

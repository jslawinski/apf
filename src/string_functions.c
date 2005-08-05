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

#include "string_functions.h"

/*
 * Function name: string_cp
 * Description: Firstly, the memory allocated for *dest is released. After this, new memory is allocated
 *              and string from src is copied to newly created location. *dest is pointing to new string.
 * Arguments: dest - pointer to pointer to string previously allocated by malloc family functions.
 *                   If dest is NULL, memory will be allocated and returned from the function. In latter
 *                   case dest will be unchanged
 *            src - string containing data for copying. If src is NULL, new memory is not allocated, but
 *                  the old one is still released.
 */

char*
string_cp(char** dest, char* src)
{
  char* tmp;
  int len = 0;
  
  /* 1. releasing memory allocated by *dest */
  if (dest != NULL) {
    if ((*dest) != NULL) {
      free((*dest));
      (*dest) = NULL;
    }
  }
  /* if src is null, there is nothing more to do */
  if (src == NULL) {
    return NULL;
  }
  /* 2. allocating new memory */
  len = strlen(src);
  tmp = calloc(1, len + 1);
  if (tmp == NULL) {
    return NULL;
  }
  /* 3. copying data from src */
  strncpy(tmp, src, len);
  if (dest != NULL) {
    (*dest) = tmp;
  }
  return tmp;
}

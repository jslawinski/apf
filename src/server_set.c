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

#include <stdlib.h>
#include <assert.h>

#include "string_functions.h"

/*
 * Function name: set_value
 * Description: If the variable has no value, set it from the given string.
 *              If the given string is NULL, use default value.
 * Arguments: dest - the destination variable
 *            from - the given string
 *            def - the default value
 */

void
set_value(char** dest, char* from, char* def)
{
  assert(dest != NULL);
  
  if ((*dest) == NULL) {
    if (from != NULL) {
      string_cp(dest, from);
    }
    else {
      (*dest) = def;
    }
  }
}

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

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include "server_check.h"
#include "stats.h"
#include "logging.h"

/*
 * Function name: check_value
 * Description: Checks if the string is a valid positive int number.
 * Arguments: what - the string representing number
 *            info - the information string printed on failure
 * Returns: The decoded int number.
 */

int
check_value(char* what, char* info)
{
  long tmp;
  
  assert(what != NULL);
  assert(info != NULL);
  
  tmp = check_value_liberal(what, info);
  
  if (tmp <= 0) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "%s: %d\n", info, tmp);
    exit(1);
  }
  return tmp;
}

/*
 * Function name: check_value_liberal
 * Description: Checks if the string is a valid int number.
 * Arguments: what - the string representing number
 *            info - the information string printed on failure
 * Returns: The decoded int number.
 */

int
check_value_liberal(char* what, char* info)
{
  char* znak;
  long tmp;

  assert(what != NULL);
  assert(info != NULL);
  
  if ((tmp = strtol(what, &znak, 10)) >= INT_MAX) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "%s: %s\n", info, what);
    exit(1);
  }
  if (((*what) == '\0') || (*znak != '\0')) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "%s: %s\n", info, what);
    exit(1);
  }
  return tmp;
}

/*
 * Function name: check_long
 * Description: Checks if the string is a valid long number.
 * Arguments: text - the string representing number
 *            number - the pointer where decoded number will be stored
 * Returns: 0 - success,
 *          1 - value from outside the long number range,
 *          2 - not the valid long number.
 */

int
check_long(char* text, long* number)
{
  char* tmp;
  if (((*number = strtol(text, &tmp, 10)) == LONG_MAX) || (*number == LONG_MIN)) {
    return 1;
  }
  if ((*text != '\0') && (*tmp == '\0')) {
    return 0;
  }
  else {
    return 2;
  }
}


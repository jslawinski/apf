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

#include "file.h"
#include "activefor.h"
#include "logging.h"
#include "network.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

int
parse_line(char* buff, char* tab1, char* tab2)
{
  int state, i, j, lastDot;
  state = i = j = 0;
  lastDot = -1;
  while (buff[i] != 0) {
    if (buff[i] == '#') {
      if ((i > 0) && (buff[i-1] == '\\')) {
        --j;
      }
      else {
        break;
      }
    }
    switch (state) {
      case 0: { /* before option name */
                if (!isspace(buff[i])) {
                  tab1[j] = buff[i];
                  j = 1;
                  state = 1;
                }
                break;
              }
      case 1: { /* option */
                if (isspace(buff[i])) {
                  tab1[j] = 0;
                  state = 2;
                  j = 0;
                }
                else {
                  tab1[j] = buff[i];
                  ++j;
                }
                break;
              }
      case 2: { /* before option value */
                if (!isspace(buff[i])) {
                  if (buff[i] != '.') {
                    tab2[j] = buff[i];
                    j = 1;
                  }
                  state = 3;
                }
                break;
              }
      case 3: { /* option value */
                if (buff[i] == '.') {
                  lastDot = j;
                }
                else if (!isspace(buff[i])) {
                  lastDot = -1;
                }
                else if (lastDot == -1) {
                  lastDot = j;
                }
                tab2[j] = buff[i];
                ++j;
                break;
              }
    }
    ++i;
  }
  if (lastDot != -1) {
    tab2[lastDot] = 0;
  }
  if (state == 3) {
    return 2;
  }
  if (state == 0) {
    return 0;
  }
  return 1;
}

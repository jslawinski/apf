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

#include <stdio.h>
#include <string.h>
#include "realmnames.h"

char*
get_realmname(ConfigurationT* config, int realm)
{
  static char realmname[10];
  
  if (config->realmtable[realm].realmname == NULL) {
    memset(realmname, 0, 10);
    sprintf(realmname, "%d", realm);
    return realmname;
  }
  
  return config->realmtable[realm].realmname;
}

int
get_realmnumber(ConfigurationT* config, char* realmname)
{
  int i;
  char guard;
  
  for (i = 0; i < config->size; ++i) {
    if (config->realmtable[i].realmname != NULL) {
      if (strcmp(realmname, config->realmtable[i].realmname) == 0) {
        return i;
      }
    }
  }

  if (sscanf(realmname, "%d%c", &i, &guard) == 1) {
    if ((i >= 0) && (i < config->size)) {
      if (config->realmtable[i].realmname == NULL) {
        return i;
      }
    }
  }
  
  return -1;
}

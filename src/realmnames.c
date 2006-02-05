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
#include <string.h>
#include <assert.h>
#include "realmnames.h"

/*
 * Function name: get_realmname
 * Description: Returns the name of the realm.
 * Arguments: config - the server configuration
 *            realm - the realm number
 * Returns: The name of the realm.
 */

char*
get_realmname(ServerConfiguration* config, int realm)
{
  static char realmname[10];

  assert(config != NULL);
  
  if (ServerRealm_get_realmName(ServerConfiguration_get_realmsTable(config)[realm]) == NULL) {
    memset(realmname, 0, 10);
    sprintf(realmname, "%d", realm);
    return realmname;
  }
  
  return ServerRealm_get_realmName(ServerConfiguration_get_realmsTable(config)[realm]);
}

/*
 * Function name: get_realmnumber
 * Description: Returns the realm number.
 * Arguments: config - the server configuration
 *            realmname - the name of the realm
 * Returns: The realm number or -1, if there is no realm with such name.
 */

int
get_realmnumber(ServerConfiguration* config, char* realmname)
{
  int i;
  char guard;
  
  assert(config != NULL);
  assert(realmname != NULL);
  
  for (i = 0; i < ServerConfiguration_get_realmsNumber(config); ++i) {
    if (ServerRealm_get_realmName(ServerConfiguration_get_realmsTable(config)[i]) != NULL) {
      if (strcmp(realmname, ServerRealm_get_realmName(ServerConfiguration_get_realmsTable(config)[i])) == 0) {
        return i;
      }
    }
  }

  if (sscanf(realmname, "%d%c", &i, &guard) == 1) {
    if ((i >= 0) && (i < ServerConfiguration_get_realmsNumber(config))) {
      if (ServerRealm_get_realmName(ServerConfiguration_get_realmsTable(config)[i]) == NULL) {
        return i;
      }
    }
  }
  
  return -1;
}

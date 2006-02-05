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
#include <assert.h>

#include "usernames.h"

/*
 * Function name: get_username
 * Description: Returns the id of the user.
 * Arguments: pointer - the server realm
 *            user - the number of the user
 * Returns: The id of the user.
 */

int
get_username(ServerRealm* pointer, int user)
{
  assert(pointer != NULL);
  return ConnectUser_get_userId(ServerRealm_get_usersTable(pointer)[user]);
}

/*
 * Function name: get_usernumber
 * Description: Returns the number of the user.
 * Arguments: pointer - the server realm
 *            user - the id of the user
 * Returns: The number of the user.
 */

int
get_usernumber(ServerRealm* pointer, int userid)
{
  int i;

  assert(pointer != NULL);

  for (i = 0; i < ServerRealm_get_usersLimit(pointer); ++i) {
    if (userid == ConnectUser_get_userId(ServerRealm_get_usersTable(pointer)[i])) {
      return i;
    }
  }

  return -1;
}

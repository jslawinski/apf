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

#include "server_eval.h"

int
eval_numofcon(RealmT* ptr, int client, int numofcon)
{
  if ((numofcon >= 0) && (numofcon < ConnectClient_get_limit(ptr->clitable[client]))) {
    numofcon = ConnectClient_get_users(ptr->clitable[client])[numofcon];
  }
  else {
    numofcon = -1;
  }
  return numofcon;
}

int
eval_usernum(ConnectClient* ptr, int usernum)
{
  int i;
  for (i = 0; i < ConnectClient_get_limit(ptr); ++i) {
    if (ConnectClient_get_users(ptr)[i] == usernum)
      return i;
  }
  return -1;
}

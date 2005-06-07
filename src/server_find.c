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

#include "server_find.h"

int
find_client(RealmT* ptr, char mode, int usrclipair)
{
  int i;
  switch(mode) {
    case 1: { /* fill first client before go to next */
              for (i = 0; i < ptr->clinum; ++i) {
                if ((ptr->clitable[i].ready == 3) && (ptr->clitable[i].whatusrcli == usrclipair)) {
                  if (ptr->clitable[i].usercon < ptr->clitable[i].usernum) {
                    return i;
                  }
                }
              }
              break;
            }
    default: {
               return 0;
             }
  }
  return 0;
}

int
find_usernum(ConnectclientT* ptr, int usernum)
{
  int i;
  for (i = 0; i < ptr->usernum; ++i) {
    if (ptr->users[i] == -1) {
      ptr->users[i] = usernum;
      return i;
    }
  }
  return -1;
}

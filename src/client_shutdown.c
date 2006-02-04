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

#include "client_shutdown.h"

void
close_connections(int usernum, ConnectUser*** contable)
{
  int i;
  if (*contable) {
    for (i = 0; i < usernum; ++i) {
      if ((ConnectUser_get_state((*contable)[i]) == S_STATE_OPEN) ||
          (ConnectUser_get_state((*contable)[i]) == S_STATE_STOPPED)) {
        close(ConnectUser_get_connFd((*contable)[i]));
      }
      ConnectUser_free(&(*contable)[i]);
    }
    free(*contable);
    (*contable) = NULL;
  }
}


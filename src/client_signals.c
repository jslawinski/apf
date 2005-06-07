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

#include "client_signals.h"
#include "thread_management.h"
#include "stats.h"
#include "logging.h"

#include <stdlib.h>

  void
client_sig_int(int signo)
{
#ifdef HAVE_LIBPTHREAD
  if (!is_this_a_mainthread()) {
    return;
  }
#endif
  aflog(LOG_T_MAIN, LOG_I_NOTICE,
      "CLIENT CLOSED cg: %ld bytes", getcg());
  exit(0);
}


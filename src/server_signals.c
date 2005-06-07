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

#include "server_signals.h"
#include "activefor.h"
#include "thread_management.h"
#include "http_proxy_functions.h"
#include "stats.h"
#include "logging.h"

extern ConfigurationT config;

  void
server_sig_int(int signo)
{
  int i, j;
  unsigned char buff[5];
  
#ifdef HAVE_LIBPTHREAD
  if (!is_this_a_mainthread()) {
    return;
  }
#endif

  for (j = 0; j < config.size; ++j) {
    buff[0] = AF_S_CLOSING; /* closing */
    for (i = 0; i < config.realmtable[j].clinum; ++i) {
      if (config.realmtable[j].clitable[i].ready == 3) {
        send_message(config.realmtable[j].type,config.realmtable[j].clitable[i].cliconn,buff,5);
      }
    }
    for (i = 0; i < config.realmtable[j].raclinum; ++i) {
      if (config.realmtable[j].raclitable[i].ready == 3) {
        send_message(config.realmtable[j].type | TYPE_SSL, config.realmtable[j].raclitable[i].cliconn, buff, 5);
      }
    }

  }

  /* FIXME: give a time to close all connections */
  mysleep(0.1);

  aflog(LOG_T_MAIN, LOG_I_NOTICE,
      "SERVER CLOSED cg: %ld bytes", getcg());
  exit(0);
}


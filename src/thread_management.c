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

#include "thread_management.h"

#ifdef HAVE_LIBPTHREAD

static pthread_t mainthread;
static pthread_mutex_t mainmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t maincond = PTHREAD_COND_INITIALIZER;

void
remember_mainthread(void)
{
  mainthread = pthread_self();
}

int
is_this_a_mainthread(void)
{
  if (pthread_self() == mainthread) {
    return 1;
  }
  return 0;
}

void
start_critical_section(void)
{
  pthread_mutex_lock( &mainmutex);
}

void
end_critical_section(void)
{
  pthread_mutex_unlock( &mainmutex);
}

void
wait_for_condition(void)
{
  pthread_cond_wait(&maincond, &mainmutex);
}

void
broadcast_condition(void)
{
  pthread_cond_broadcast(&maincond);
}

#endif
